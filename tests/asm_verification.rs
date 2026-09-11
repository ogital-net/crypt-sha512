// Integration test to verify OPENSSL_cleanse is present in compiled code
// This test must be run with --ignored flag and will generate assembly output

#[test]
#[ignore]
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn verify_openssl_cleanse_in_assembly() {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    println!("\n=== Verifying OPENSSL_cleanse is not optimized out ===\n");

    // Clean previous builds
    println!("Cleaning previous builds...");
    let clean_status = Command::new("cargo")
        .args(["clean"])
        .status()
        .expect("Failed to run cargo clean");
    assert!(clean_status.success(), "cargo clean failed");

    // Build with assembly emission in release mode
    println!("Building release with assembly output...");
    let build_status = Command::new("cargo")
        .args([
            "rustc",
            "--release",
            "--lib",
            "--",
            "--emit",
            "asm",
            "-C",
            "llvm-args=-x86-asm-syntax=intel",
        ])
        .status()
        .expect("Failed to build with assembly");
    assert!(build_status.success(), "cargo rustc failed");

    // Find the assembly file
    println!("Searching for assembly files...");
    let target_dir = PathBuf::from("target/release/deps");

    let mut asm_files = Vec::new();
    if let Ok(entries) = fs::read_dir(&target_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "s"
                    && path
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("crypt_sha512_rs")
                {
                    asm_files.push(path);
                }
            }
        }
    }

    assert!(!asm_files.is_empty(), "No assembly files found!");
    println!("Found {} assembly file(s)", asm_files.len());

    // Check each assembly file for OPENSSL_cleanse
    let mut total_cleanse_calls = 0;

    for asm_file in &asm_files {
        println!("\nChecking: {}", asm_file.display());
        let content = fs::read_to_string(asm_file).expect("Failed to read assembly file");

        let cleanse_calls = content.matches("OPENSSL_cleanse").count();
        println!("  Found {} OPENSSL_cleanse call(s)", cleanse_calls);

        total_cleanse_calls += cleanse_calls;

        // Print some context around the calls
        for (line_num, line) in content.lines().enumerate() {
            if line.contains("OPENSSL_cleanse") {
                println!("  Line {}: {}", line_num + 1, line.trim());
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total OPENSSL_cleanse calls found: {}", total_cleanse_calls);
    println!("Expected locations:");
    println!("  1. Sha512Context::drop");
    println!("  2. crypt_sha512 (for alt_result, p_bytes, s_bytes)");
    println!("  3. hash_password (for salt_bytes)");

    // We expect at least 3 calls (one in Drop, multiple in crypt_sha512, one in hash_password)
    assert!(
        total_cleanse_calls >= 3,
        "Expected at least 3 OPENSSL_cleanse calls, found {}. \
        This indicates the compiler may have optimized out security-critical memory clearing!",
        total_cleanse_calls
    );

    println!("\n[OK] OPENSSL_cleanse is present and not optimized out!");
}
