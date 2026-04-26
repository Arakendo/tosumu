pub const FILE_IO_FAILED: &str = "FILE_IO_FAILED";
pub const RECORD_CORRUPT: &str = "RECORD_CORRUPT";
pub const PAGE_DECODE_CORRUPT: &str = "PAGE_DECODE_CORRUPT";
pub const PAGE_AUTH_TAG_FAILED: &str = "PAGE_AUTH_TAG_FAILED";
pub const PAGE_ENCRYPT_FAILED: &str = "PAGE_ENCRYPT_FAILED";
pub const RNG_UNAVAILABLE: &str = "RNG_UNAVAILABLE";
pub const FILE_TRUNCATED: &str = "FILE_TRUNCATED";
pub const HANDLE_POISONED: &str = "HANDLE_POISONED";
pub const FORMAT_NOT_TOSUMU: &str = "FORMAT_NOT_TOSUMU";
pub const FORMAT_VERSION_UNSUPPORTED: &str = "FORMAT_VERSION_UNSUPPORTED";
pub const PAGE_SIZE_MISMATCH: &str = "PAGE_SIZE_MISMATCH";
pub const STORAGE_OUT_OF_SPACE: &str = "STORAGE_OUT_OF_SPACE";
pub const ARGUMENT_INVALID: &str = "ARGUMENT_INVALID";
pub const INSPECT_PAGE_OUT_OF_RANGE: &str = "INSPECT_PAGE_OUT_OF_RANGE";
pub const FILE_OPEN_BUSY: &str = "FILE_OPEN_BUSY";
pub const PROTECTOR_UNLOCK_WRONG_KEY: &str = "PROTECTOR_UNLOCK_WRONG_KEY";
pub const COMMITTED_FLUSH_FAILED: &str = "COMMITTED_FLUSH_FAILED";

pub const PUBLIC_CODES: &[&str] = &[
    FILE_IO_FAILED,
    RECORD_CORRUPT,
    PAGE_DECODE_CORRUPT,
    PAGE_AUTH_TAG_FAILED,
    PAGE_ENCRYPT_FAILED,
    RNG_UNAVAILABLE,
    FILE_TRUNCATED,
    HANDLE_POISONED,
    FORMAT_NOT_TOSUMU,
    FORMAT_VERSION_UNSUPPORTED,
    PAGE_SIZE_MISMATCH,
    STORAGE_OUT_OF_SPACE,
    ARGUMENT_INVALID,
    INSPECT_PAGE_OUT_OF_RANGE,
    FILE_OPEN_BUSY,
    PROTECTOR_UNLOCK_WRONG_KEY,
    COMMITTED_FLUSH_FAILED,
];

#[cfg(test)]
mod tests {
    use super::PUBLIC_CODES;

    #[test]
    fn documented_public_codes_match_exported_constants() {
        let errors_md_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("ERRORS.md");
        let errors_md = std::fs::read_to_string(&errors_md_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", errors_md_path.display()));

        let documented = extract_marked_code_block(
            &errors_md,
            "<!-- BEGIN_CORE_PUBLIC_CODES -->",
            "<!-- END_CORE_PUBLIC_CODES -->",
        );

        assert_eq!(documented, PUBLIC_CODES);
    }

    fn extract_marked_code_block<'a>(
        document: &'a str,
        start_marker: &str,
        end_marker: &str,
    ) -> Vec<&'a str> {
        let after_start = document
            .split_once(start_marker)
            .unwrap_or_else(|| panic!("missing start marker {start_marker}"))
            .1;
        let before_end = after_start
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("missing end marker {end_marker}"))
            .0;
        let code_block = before_end
            .split_once("```txt")
            .unwrap_or_else(|| panic!("missing txt code block after {start_marker}"))
            .1
            .split_once("```")
            .unwrap_or_else(|| panic!("missing closing code fence before {end_marker}"))
            .0;

        code_block
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    }
}
