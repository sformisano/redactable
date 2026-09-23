//! `Sensitive`, `SensitiveDisplay`, and `SensitiveDual` expansion.
//!
//! This module assembles the trait implementations emitted by the structural
//! (`Sensitive`) and display (`SensitiveDisplay`) halves, including shared
//! option handling and the slog/tracing integration impls. `SensitiveDual` runs
//! both halves from one authenticated entry point.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{Attribute, DeriveInput, Error, Generics, Result, WherePredicate};
#[cfg(feature = "tracing")]
use syn::{ImplGenerics, TypeGenerics, WhereClause};
#[cfg(feature = "slog")]
use syn::{Type, parse_quote};

use crate::{
    container::{
        Body, ContainerOptions, parse_container_options, reject_field_only_container_attrs,
    },
    crate_paths::{crate_root, isolate_generated_items},
    declaration::declaration_check,
    derive_enum::derive_enum,
    derive_struct::derive_struct,
    fresh_ident::FreshIdentAllocator,
    generics::add_predicates,
    output::{display_to_redacted_impl, dual_to_redacted_impl, structural_to_redacted_impl},
    redacted_display::derive_redacted_display,
};

/// Output produced by struct/enum derive logic for the structural half.
///
/// Shared by `derive_struct`, `derive_enum`, and the top-level `expand()`.
pub(crate) struct DeriveOutput {
    pub(crate) redaction_body: TokenStream,
    /// Traversal and policy bounds shared by every emitted structural impl.
    pub(crate) predicates: Vec<WherePredicate>,
    pub(crate) debug_redacted_body: TokenStream,
    /// Extra bounds only the generated `Debug` impl needs.
    pub(crate) debug_predicates: Vec<WherePredicate>,
}

/// Which derive macro invoked [`expand`].
#[derive(Clone, Copy)]
pub(crate) enum Expansion {
    /// `#[derive(Sensitive)]`: the structural half alone.
    Sensitive,
    /// `#[derive(SensitiveDisplay)]`: the display half alone.
    SensitiveDisplay,
    /// `#[derive(SensitiveDual)]`: both halves from one authenticated expansion.
    Dual,
}

/// One half of an expansion, and whether its twin is emitted beside it.
///
/// The dual variants exist only inside [`expand`], so no other entry point can
/// request a half that skips its `Debug` or logging impls on the assumption
/// that a twin provides them.
#[derive(Clone, Copy)]
enum Half {
    Sensitive,
    SensitiveDisplay,
    DualStructural,
    DualDisplay,
}

impl Half {
    fn is_dual(self) -> bool {
        matches!(self, Self::DualStructural | Self::DualDisplay)
    }

    fn derive_name(self) -> &'static str {
        match self {
            Self::Sensitive | Self::DualStructural => "Sensitive",
            Self::SensitiveDisplay | Self::DualDisplay => "SensitiveDisplay",
        }
    }
}

pub(crate) fn expand(input: DeriveInput, expansion: Expansion) -> Result<TokenStream> {
    match expansion {
        Expansion::Sensitive => expand_half(input, Half::Sensitive),
        Expansion::SensitiveDisplay => expand_half(input, Half::SensitiveDisplay),
        Expansion::Dual => {
            let structural = expand_half(input.clone(), Half::DualStructural);
            let display = expand_half(input, Half::DualDisplay);
            match (structural, display) {
                (Ok(structural), Ok(display)) => Ok(quote!(#structural #display)),
                (Err(mut first), Err(second)) => {
                    first.combine(second);
                    Err(first)
                }
                (Err(err), _) | (_, Err(err)) => Err(err),
            }
        }
    }
}

fn expand_half(input: DeriveInput, half: Half) -> Result<TokenStream> {
    let mut fresh = FreshIdentAllocator::new(&input);
    let DeriveInput {
        ident,
        generics,
        data,
        attrs,
        ..
    } = input;

    reject_field_only_container_attrs(&attrs)?;
    let ContainerOptions {
        dual: requested_dual,
    } = parse_container_options(&attrs)?;
    if requested_dual && !half.is_dual() {
        return Err(Error::new(
            ident.span(),
            "`#[sensitive(dual)]` is no longer accepted on `Sensitive` or `SensitiveDisplay`; use `#[derive(SensitiveDual)]` instead",
        ));
    }
    let body = Body::new(data, half.derive_name())?;
    let formatter = fresh.fresh("__redactable_f");

    match half {
        Half::Sensitive | Half::DualStructural => {
            let mapper = fresh.fresh("__redactable_mapper");
            let mapper_type = fresh.fresh("__RedactableMapper");
            expand_structural(
                ident,
                generics,
                body,
                &mut fresh,
                half.is_dual(),
                formatter,
                (mapper, mapper_type),
            )
        }
        Half::SensitiveDisplay | Half::DualDisplay => expand_display(
            ident,
            generics,
            body,
            attrs,
            &mut fresh,
            half.is_dual(),
            formatter,
        ),
    }
}

/// Assembles the impls emitted by `SensitiveDisplay`: `RedactableWithFormatter`,
/// `ToRedacted`, production-consistent `Debug`, and — outside dual mode — the
/// slog/tracing integration impls.
fn expand_display(
    ident: Ident,
    generics: Generics,
    body: Body,
    attrs: Vec<Attribute>,
    fresh: &mut FreshIdentAllocator,
    dual: bool,
    formatter: Ident,
) -> Result<TokenStream> {
    let crate_root = crate_root();
    let redacted_display_output =
        derive_redacted_display(&ident, &body, &attrs, &formatter, fresh)?;
    let redacted_display_generics = add_predicates(
        generics.clone(),
        &redacted_display_output.predicates,
        &ident,
    );
    let (display_impl_generics, display_ty_generics, display_where_clause) =
        redacted_display_generics.split_for_impl();
    let redacted_display_body = redacted_display_output.body;
    let check_name = fresh.fresh("__redactable_check_display_declaration");
    let declaration = declaration_check(
        &ident,
        &generics,
        quote! {
            fn #check_name(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #redacted_display_body
            }
        },
    );
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

    // In dual mode, the structural half provides slog and tracing impls.
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
        #declaration
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
fn expand_structural(
    ident: Ident,
    generics: Generics,
    body: Body,
    fresh: &mut FreshIdentAllocator,
    dual: bool,
    formatter: Ident,
    mapper_idents: (Ident, Ident),
) -> Result<TokenStream> {
    let crate_root = crate_root();
    // Inverse of the display half: a dual type gets its single producer there.
    let to_redacted_impl = if dual {
        quote! {}
    } else {
        structural_to_redacted_impl(&ident, &generics, &crate_root)
    };
    let (mapper, mapper_type) = mapper_idents;

    let derive_output = match body {
        Body::Struct(data) => derive_struct(&ident, data, &formatter, &mapper, fresh)?,
        Body::Enum(data) => derive_enum(&ident, data, &formatter, &mapper, fresh)?,
    };

    let policy_generics = add_predicates(generics.clone(), &derive_output.predicates, &ident);
    let (impl_generics, ty_generics, where_clause) = policy_generics.split_for_impl();
    #[cfg(feature = "slog")]
    let slog_base_generics = generics.clone();
    let debug_generics = add_predicates(
        policy_generics.clone(),
        &derive_output.debug_predicates,
        &ident,
    );
    let (debug_impl_generics, debug_ty_generics, debug_where_clause) =
        debug_generics.split_for_impl();
    let redaction_body = &derive_output.redaction_body;
    let debug_redacted_body = &derive_output.debug_redacted_body;
    let check_name = fresh.fresh("__redactable_check_structural_declaration");
    let declaration = declaration_check(
        &ident,
        &generics,
        quote! {
            fn #check_name<#mapper_type: #crate_root::RedactableMapper>(self, #mapper: &#mapper_type) -> Self {
                use #crate_root::RedactableWithMapper as _;
                #redaction_body
            }
        },
    );
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
        #declaration
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

/// Assembles the `slog::Value` and `SlogRedacted` impls emitted for a type whose
/// redacted text comes from `RedactableWithFormatter`.
///
/// `SensitiveDisplay` and `NotSensitiveDisplay` share this exact body.
#[cfg(feature = "slog")]
pub(crate) fn assemble_display_slog_impl(
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
