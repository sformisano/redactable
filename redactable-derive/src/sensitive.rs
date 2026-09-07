//! `Sensitive` and `SensitiveDisplay` expansion.
//!
//! This module assembles the trait implementations emitted by the structural
//! (`Sensitive`) and display (`SensitiveDisplay`) derives, including shared
//! option handling and the slog/tracing integration impls.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{
    Attribute, Data, DeriveInput, Error, Field, Fields, Generics, Result, WherePredicate,
    spanned::Spanned,
};
#[cfg(feature = "tracing")]
use syn::{ImplGenerics, TypeGenerics, WhereClause};
#[cfg(feature = "slog")]
use syn::{Type, parse_quote};

use crate::{
    container::{
        ContainerOptions, parse_container_options, reject_field_only_container_attrs,
        reject_removed_output_option,
    },
    crate_paths::{crate_root, isolate_generated_items},
    derive_enum::derive_enum,
    derive_struct::derive_struct,
    fresh_ident::FreshIdentAllocator,
    generics::add_predicates,
    output::{display_to_redacted_impl, dual_to_redacted_impl, structural_to_redacted_impl},
    redacted_display::derive_redacted_display,
    strategy::parse_redactable_field_options,
};

/// Output produced by struct/enum derive logic for `Sensitive`.
///
/// Shared by `derive_struct`, `derive_enum`, and the top-level `expand()`.
pub(crate) struct DeriveOutput {
    pub(crate) redaction_body: TokenStream,
    pub(crate) used_generics: Vec<WherePredicate>,
    pub(crate) policy_applicable_generics: Vec<WherePredicate>,
    pub(crate) debug_redacted_body: TokenStream,
    pub(crate) debug_generics: Vec<WherePredicate>,
}

/// Which derive macro invoked `expand()`.
///
/// Controls what impls are generated: `Sensitive` emits `RedactableWithMapper` (structural
/// traversal), while `SensitiveDisplay` emits `RedactableWithFormatter` (display formatting).
pub(crate) enum DeriveKind {
    /// `#[derive(Sensitive)]` — structural redaction via `RedactableWithMapper`.
    Sensitive,
    /// `#[derive(SensitiveDisplay)]` — display formatting via `RedactableWithFormatter`.
    SensitiveDisplay,
}

/// Output choices established by the authenticated derive entry point.
struct ExpansionMode {
    dual: bool,
}

pub(crate) fn expand(input: DeriveInput, kind: DeriveKind) -> Result<TokenStream> {
    expand_with_mode(input, kind, false)
}

pub(crate) fn expand_with_mode(
    input: DeriveInput,
    kind: DeriveKind,
    authenticated_dual: bool,
) -> Result<TokenStream> {
    let mut fresh = FreshIdentAllocator::new(&input);
    let DeriveInput {
        ident,
        generics,
        data,
        attrs,
        ..
    } = input;

    reject_removed_output_option(&attrs)?;
    reject_field_only_container_attrs(&attrs)?;
    let ContainerOptions {
        dual: requested_dual,
    } = parse_container_options(&attrs)?;
    if requested_dual && !authenticated_dual {
        return Err(Error::new(
            ident.span(),
            "`#[sensitive(dual)]` is no longer accepted on `Sensitive` or `SensitiveDisplay`; use `#[derive(SensitiveDual)]` instead",
        ));
    }
    if matches!(&kind, DeriveKind::Sensitive) && !authenticated_dual {
        reject_display_only_field_options(&data)?;
    }
    let mode = ExpansionMode {
        dual: authenticated_dual,
    };
    let formatter = fresh.fresh("__redactable_f");
    let mapper = fresh.fresh("__redactable_mapper");
    let mapper_type = fresh.fresh("__RedactableMapper");

    if matches!(kind, DeriveKind::SensitiveDisplay) {
        return expand_sensitive_display(ident, generics, data, attrs, &mut fresh, mode, formatter);
    }

    // Only DeriveKind::Sensitive reaches this point (SensitiveDisplay returns early above).
    expand_sensitive(
        ident,
        generics,
        data,
        &mut fresh,
        mode,
        formatter,
        (mapper, mapper_type),
    )
}

/// Assembles the impls emitted by `SensitiveDisplay`: `RedactableWithFormatter`,
/// `ToRedacted`, production-consistent `Debug`, and — outside dual mode — the
/// slog/tracing integration impls.
fn expand_sensitive_display(
    ident: Ident,
    generics: Generics,
    data: Data,
    attrs: Vec<Attribute>,
    fresh: &mut FreshIdentAllocator,
    mode: ExpansionMode,
    formatter: Ident,
) -> Result<TokenStream> {
    let ExpansionMode { dual } = mode;
    let crate_root = crate_root();
    let redacted_display_output =
        derive_redacted_display(&ident, &data, &attrs, &generics, &formatter, fresh)?;
    let redacted_display_generics = add_predicates(
        generics.clone(),
        &redacted_display_output.display_generics,
        &ident,
    );
    let redacted_display_generics = add_predicates(
        redacted_display_generics,
        &redacted_display_output.debug_generics,
        &ident,
    );
    let redacted_display_generics = add_predicates(
        redacted_display_generics,
        &redacted_display_output.policy_ref_generics,
        &ident,
    );
    let redacted_display_generics = add_predicates(
        redacted_display_generics,
        &redacted_display_output.nested_generics,
        &ident,
    );
    let (display_impl_generics, display_ty_generics, display_where_clause) =
        redacted_display_generics.split_for_impl();
    let redacted_display_body = redacted_display_output.body;
    let redacted_display_impl = quote! {
        impl #display_impl_generics #crate_root::RedactableWithFormatter for #ident #display_ty_generics #display_where_clause {
            fn fmt_redacted(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #redacted_display_body
            }
        }

        impl #display_impl_generics #crate_root::__private::DeclaredFormatting for #ident #display_ty_generics #display_where_clause {}
    };
    // The display half owns the producer in dual mode: it is the half that
    // knows the template, and only one impl may exist per type.
    let to_redacted_impl = if dual {
        dual_to_redacted_impl(&ident, &redacted_display_generics, &crate_root)
    } else {
        display_to_redacted_impl(&ident, &redacted_display_generics, &crate_root)
    };

    // Debug always uses the same selected template as redacted display.
    let debug_impl = quote! {
        impl #display_impl_generics ::core::fmt::Debug for #ident #display_ty_generics #display_where_clause {
            fn fmt(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #crate_root::RedactableWithFormatter::fmt_redacted(self, #formatter)
            }
        }
    };

    // In dual mode, Sensitive provides slog and tracing impls — skip them here.
    let slog_impl = if dual {
        quote! {}
    } else {
        #[cfg(feature = "slog")]
        {
            assemble_display_slog_impl(fresh, generics, &ident, &crate_root)
        }

        #[cfg(not(feature = "slog"))]
        {
            quote! {}
        }
    };

    let tracing_impl = if dual {
        quote! {}
    } else {
        #[cfg(feature = "tracing")]
        {
            assemble_display_tracing_impl(&redacted_display_generics, &crate_root, &ident)
        }

        #[cfg(not(feature = "tracing"))]
        {
            quote! {}
        }
    };

    let generated = quote! {
        #redacted_display_impl
        #to_redacted_impl
        #debug_impl
        #slog_impl
        #tracing_impl
    };
    Ok(isolate_generated_items(generated, fresh))
}

/// Assembles the impls emitted by `Sensitive`: `RedactableWithMapper`, `Redactable`,
/// `ToRedacted`, production-consistent `Debug`, and the slog/tracing integration impls.
fn expand_sensitive(
    ident: Ident,
    generics: Generics,
    data: Data,
    fresh: &mut FreshIdentAllocator,
    mode: ExpansionMode,
    formatter: Ident,
    mapper_idents: (Ident, Ident),
) -> Result<TokenStream> {
    let ExpansionMode { dual } = mode;
    let crate_root = crate_root();
    // Inverse of the display half: a dual type gets its single producer there.
    let to_redacted_impl = if dual {
        quote! {}
    } else {
        structural_to_redacted_impl(&ident, &generics, &crate_root)
    };
    let (mapper, mapper_type) = mapper_idents;

    let derive_output = match data {
        Data::Struct(data) => derive_struct(&ident, data, &generics, &formatter, &mapper, fresh)?,
        Data::Enum(data) => derive_enum(&ident, data, &generics, &formatter, &mapper, fresh)?,
        Data::Union(u) => {
            return Err(Error::new(
                u.union_token.span(),
                "`Sensitive` cannot be derived for unions",
            ));
        }
    };

    let policy_generics = add_predicates(generics.clone(), &derive_output.used_generics, &ident);
    let policy_generics = add_predicates(
        policy_generics,
        &derive_output.policy_applicable_generics,
        &ident,
    );
    let (impl_generics, ty_generics, where_clause) = policy_generics.split_for_impl();
    #[cfg(feature = "slog")]
    let slog_base_generics = generics.clone();
    let debug_generics = add_predicates(generics, &derive_output.debug_generics, &ident);
    let (debug_impl_generics, debug_ty_generics, debug_where_clause) =
        debug_generics.split_for_impl();
    let redaction_body = &derive_output.redaction_body;
    let debug_redacted_body = &derive_output.debug_redacted_body;
    // Dual gets Debug from its display expansion; standalone Sensitive retains
    // its annotation-driven production placeholders in every build mode.
    let debug_impl = if dual {
        quote! {}
    } else {
        quote! {
            impl #debug_impl_generics ::core::fmt::Debug for #ident #debug_ty_generics #debug_where_clause {
                fn fmt(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    #debug_redacted_body
                }
            }
        }
    };

    #[cfg(feature = "slog")]
    let slog_impl = assemble_sensitive_slog_impl(fresh, slog_base_generics, &ident, &crate_root);

    #[cfg(not(feature = "slog"))]
    let slog_impl = quote! {};

    #[cfg(feature = "tracing")]
    let tracing_impl = assemble_sensitive_tracing_impl(
        &impl_generics,
        &ty_generics,
        where_clause,
        &ident,
        &crate_root,
    );

    #[cfg(not(feature = "tracing"))]
    let tracing_impl = quote! {};

    let trait_impl = quote! {
        impl #impl_generics #crate_root::RedactableWithMapper for #ident #ty_generics #where_clause {
            fn redact_with<#mapper_type: #crate_root::RedactableMapper>(self, #mapper: &#mapper_type) -> Self {
                use #crate_root::RedactableWithMapper as _;
                #redaction_body
            }
        }

        impl #impl_generics #crate_root::Redactable for #ident #ty_generics #where_clause {}

        #to_redacted_impl

        #debug_impl

        #slog_impl

        #tracing_impl

    };
    Ok(isolate_generated_items(trait_impl, fresh))
}

/// Rejects formatting-only field options when no display derive consumes them.
fn reject_display_only_field_options(data: &Data) -> Result<()> {
    fn check_field(field: &Field) -> Result<()> {
        let options = parse_redactable_field_options(&field.attrs)?;
        if options.legacy_formatting || options.generated_formatting {
            let span = field
                .attrs
                .iter()
                .find(|attr| attr.path().is_ident("redactable"))
                .map_or_else(|| field.span(), Spanned::span);
            return Err(Error::new(
                span,
                "formatting route overrides are only used by `SensitiveDisplay`; use `SensitiveDual` when structural and display redaction are both needed",
            ));
        }
        Ok(())
    }

    fn check_fields(fields: &Fields) -> Result<()> {
        for field in fields {
            check_field(field)?;
        }
        Ok(())
    }

    match data {
        Data::Struct(data) => check_fields(&data.fields),
        Data::Enum(data) => {
            for variant in &data.variants {
                check_fields(&variant.fields)?;
            }
            Ok(())
        }
        Data::Union(data) => {
            for field in &data.fields.named {
                check_field(field)?;
            }
            Ok(())
        }
    }
}

/// Assembles the `slog::Value` and `SlogRedacted` impls emitted by `SensitiveDisplay`.
#[cfg(feature = "slog")]
fn assemble_display_slog_impl(
    fresh: &mut FreshIdentAllocator,
    generics: Generics,
    ident: &Ident,
    crate_root: &TokenStream,
) -> TokenStream {
    let record = fresh.fresh("__redactable_record");
    let key = fresh.fresh("key");
    let serializer = fresh.fresh("serializer");
    let redacted = fresh.fresh("__redactable_value");
    let slog_crate = quote! { #crate_root::__private::slog };
    let mut slog_generics = generics;
    let (_, ty_generics, _) = slog_generics.split_for_impl();
    let self_ty: Type = parse_quote!(#ident #ty_generics);
    slog_generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(#self_ty: #crate_root::RedactableWithFormatter));
    let (slog_impl_generics, slog_ty_generics, slog_where_clause) = slog_generics.split_for_impl();
    quote! {
        impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
            fn serialize(
                &self,
                #record: &#slog_crate::Record<'_>,
                #key: #slog_crate::Key,
                #serializer: &mut dyn #slog_crate::Serializer,
            ) -> #slog_crate::Result {
                let #redacted = #crate_root::RedactableWithFormatter::redacted_display(self);
                #serializer.emit_arguments(#key, &format_args!("{}", #redacted))
            }
        }

        impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
    }
}

/// Assembles the `TracingRedacted` marker impl emitted by `SensitiveDisplay`.
#[cfg(feature = "tracing")]
fn assemble_display_tracing_impl(
    redacted_display_generics: &Generics,
    crate_root: &TokenStream,
    ident: &Ident,
) -> TokenStream {
    let (tracing_impl_generics, tracing_ty_generics, tracing_where_clause) =
        redacted_display_generics.split_for_impl();
    quote! {
        impl #tracing_impl_generics #crate_root::tracing::TracingRedacted for #ident #tracing_ty_generics #tracing_where_clause {}
    }
}

/// Assembles the fail-closed `slog::Value` and `SlogRedacted` impls emitted by `Sensitive`.
#[cfg(feature = "slog")]
fn assemble_sensitive_slog_impl(
    fresh: &mut FreshIdentAllocator,
    slog_base_generics: Generics,
    ident: &Ident,
    crate_root: &TokenStream,
) -> TokenStream {
    let record = fresh.fresh("__redactable_record");
    let key = fresh.fresh("key");
    let serializer = fresh.fresh("serializer");
    let redacted = fresh.fresh("__redactable_value");
    let slog_crate = quote! { #crate_root::__private::slog };
    let slog_generics = slog_base_generics;
    let (slog_impl_generics, slog_ty_generics, slog_where_clause) = slog_generics.split_for_impl();
    quote! {
        impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
            fn serialize(
                &self,
                #record: &#slog_crate::Record<'_>,
                #key: #slog_crate::Key,
                #serializer: &mut dyn #slog_crate::Serializer,
            ) -> #slog_crate::Result {
                // `slog::Value` receives only `&self`. Stable Rust cannot prove
                // that cloning or serializing that reference is observation-free
                // for arbitrary fields, so generated borrowed logging fails closed.
                // Callers that accept the clone can opt into structured output
                // with `SlogRedactedExt::slog_redacted_json`.
                let #redacted = #crate_root::__private::generated_redacted_json_placeholder();
                #slog_crate::Value::serialize(&#redacted, #record, #key, #serializer)
            }
        }

        impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
    }
}

/// Assembles the `TracingRedacted` marker impl emitted by `Sensitive`.
#[cfg(feature = "tracing")]
fn assemble_sensitive_tracing_impl(
    impl_generics: &ImplGenerics<'_>,
    ty_generics: &TypeGenerics<'_>,
    where_clause: Option<&WhereClause>,
    ident: &Ident,
    crate_root: &TokenStream,
) -> TokenStream {
    quote! {
        impl #impl_generics #crate_root::tracing::TracingRedacted for #ident #ty_generics #where_clause {}
    }
}
