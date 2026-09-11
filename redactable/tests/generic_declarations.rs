//! Declaration admission is checked without calling any generated method.

use trybuild::TestCases;
#[test]
fn generic_declarations_require_their_capabilities() {
    let cases = TestCases::new();
    cases.compile_fail("tests/ui/generic_declaration_*_missing.rs");
    cases.pass("tests/ui/generic_declaration_*_ok.rs");
}
