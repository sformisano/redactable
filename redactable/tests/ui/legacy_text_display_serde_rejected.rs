#![allow(deprecated)]

use std::fmt::Display;

use redactable::BypassTextRedaction;
use serde::{Deserialize, Serialize};

fn needs_display<T: Display>() {}
fn needs_serialize<T: Serialize>() {}
fn needs_deserialize<T: for<'de> Deserialize<'de>>() {}

fn main() {
    needs_display::<BypassTextRedaction>();
    needs_serialize::<BypassTextRedaction>();
    needs_deserialize::<BypassTextRedaction>();
}
