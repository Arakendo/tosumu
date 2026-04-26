// build.rs for tosumu-bench
//
// Two build modes:
//
//   bundled-sqlite (default):
//     rusqlite compiles its own sqlite3.c amalgamation.
//     Nothing to do here.
//
//   sqlite-see (--no-default-features --features sqlite-see):
//     Compiles a SQLite SEE amalgamation from SQLITE_SEE_DIR.
//     The compiled static lib is named "sqlite3" so rusqlite links against it
//     instead of the system sqlite3.
//
//     Required env vars:
//       SQLITE_SEE_DIR  — path to directory containing the SEE .c source files
//                         (e.g. F:\LocalSource\ClassLibrary\sqlite-see-efcore\see-sources)
//
//     Optional env vars:
//       SQLITE_SEE_SRC  — filename within SQLITE_SEE_DIR to compile
//                         Default: sqlite3-see-aes256-ofb.c
//                         Other options: sqlite3-see.c, sqlite3-see-aes128-ccm.c,
//                                        sqlite3-see-aes256-cryptoapi.c (Windows only)
//
// After a successful SEE compile, build.rs emits:
//   cargo:rustc-cfg=sqlite_see
// which gates the encrypted benchmark groups in benches/btree_vs_sqlite.rs.

fn main() {
    println!("cargo:rerun-if-env-changed=SQLITE_SEE_DIR");
    println!("cargo:rerun-if-env-changed=SQLITE_SEE_SRC");
    // Always declare the cfg key so the compiler doesn't warn about unknown cfgs
    // even when the SEE branch isn't taken.
    println!("cargo:rustc-check-cfg=cfg(sqlite_see)");

    // If bundled-sqlite feature is active, rusqlite handles everything.
    if std::env::var("CARGO_FEATURE_BUNDLED_SQLITE").is_ok() {
        return;
    }

    // sqlite-see mode: compile SEE from the local path.
    let see_dir = std::env::var("SQLITE_SEE_DIR").unwrap_or_else(|_| {
        panic!(
            "\n\ntosumu-bench: `sqlite-see` mode requires the SQLITE_SEE_DIR environment variable.\n\
             Point it to the directory containing the SEE source files.\n\
             Example (PowerShell):\n\
               $env:SQLITE_SEE_DIR = \
               'F:\\LocalSource\\ClassLibrary\\sqlite-see-efcore\\see-sources'\n\
               cargo bench --no-default-features --features sqlite-see\n\n"
        )
    });

    let see_src =
        std::env::var("SQLITE_SEE_SRC").unwrap_or_else(|_| "sqlite3-see-aes256-ofb.c".to_owned());

    let see_dir_path = std::path::PathBuf::from(&see_dir);
    let see_src_path = see_dir_path.join(&see_src);

    assert!(
        see_src_path.exists(),
        "tosumu-bench: SEE source not found at {}\n\
         Check SQLITE_SEE_DIR ({see_dir}) and SQLITE_SEE_SRC ({see_src}).",
        see_src_path.display()
    );

    cc::Build::new()
        .file(&see_src_path)
        .include(&see_dir_path) // sqlite3.h lives alongside the .c files
        .define("SQLITE_HAS_CODEC", None)
        .define("SQLITE_TEMP_STORE", Some("2"))
        .define("NDEBUG", None)
        .opt_level(2)
        .compile("sqlite3");

    // Signal the bench code that SEE-encrypted benches should be compiled in.
    println!("cargo:rustc-check-cfg=cfg(sqlite_see)");
    println!("cargo:rustc-cfg=sqlite_see");

    // Windows VFS requires these.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=advapi32");
    }
}
