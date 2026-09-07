//! Bounded consumer proof for Axis's selected-output logging boundary.
//!
//! Source: github.com/sformisano/axis at
//! `14417ae77286e45a7d4dbbd8e674a9a6cc091397`.
//! This fixture ports field routing and tracing capture for the tested JSON
//! shapes. It does not build Axis or reproduce its complete custom serializer.

#[cfg(test)]
mod capture;
#[cfg(test)]
mod logging;
#[cfg(test)]
mod models;
#[cfg(test)]
mod selected_contracts;
#[cfg(test)]
mod tests;
