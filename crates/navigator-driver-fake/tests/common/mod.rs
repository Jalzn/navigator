pub mod pi_package;

#[allow(dead_code, reason = "shared helper is used by a subset of test crates")]
pub fn valid_trusted_configuration(base_instructions: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "base_instructions": base_instructions,
        "secret_names": [],
        "navigator_tool_catalog": [],
    }))
    .unwrap()
}
