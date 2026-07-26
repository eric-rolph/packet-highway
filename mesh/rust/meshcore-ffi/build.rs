//! Generates `include/meshcore.h` from the `extern "C"` surface.
//!
//! The header is committed-adjacent (written into `include/`, gitignored) and
//! copied into the CocoaPod and the Android CMake include path by the build
//! scripts. Generating rather than hand-writing it means the C declarations can
//! never drift from the Rust definitions — the class of bug that shows up as a
//! silently corrupted struct three frames into ObjC.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/c_api.rs");
    println!("cargo:rerun-if-changed=src/buffer.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // Skip during `cargo publish`/docs.rs-style builds where the crate dir is
    // read-only, and when the caller only wants the rlib for host tests.
    if std::env::var_os("MESHCORE_SKIP_CBINDGEN").is_some() {
        return;
    }

    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = crate_dir.join("include").join("meshcore.h");
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => {
            bindings.write_to_file(&out);
        }
        Err(e) => {
            // A cbindgen failure must not break `cargo test` on the host.
            println!("cargo:warning=cbindgen failed: {e}");
        }
    }
}
