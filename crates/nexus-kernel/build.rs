fn main() {
    println!("cargo:rerun-if-env-changed=NEXUS_FIXTURES_DIR");
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if std::env::var_os("CARGO_FEATURE_HARDENING_TESTS").is_none()
        || !matches!(target.as_str(), "uefi" | "none")
    {
        return;
    }
    let root = std::env::var_os("NEXUS_FIXTURES_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
                .join("../../build/fixtures")
        });
    let root = root
        .canonicalize()
        .expect("Run scripts/build-fixtures.py before the hardening guest build");
    for mode in 0..16 {
        for (prefix, suffix) in [("pe", "exe"), ("elf", "elf")] {
            let path = root.join(format!("{prefix}-{mode}.{suffix}"));
            assert!(
                path.is_file(),
                "Missing external fixture: {}",
                path.display()
            );
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    println!("cargo:rustc-env=NEXUS_FIXTURES_DIR={}", root.display());
}
