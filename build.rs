fn main() {
    println!("cargo:rerun-if-env-changed=PILLOWLOCK_UPDATE_REPO");
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-light".into());
    slint_build::compile_with_config("ui/app.slint", config).unwrap();
    #[cfg(target_os = "windows")]
    let _ = embed_resource::compile("assets/branding/pillowlock.rc", embed_resource::NONE);
}
