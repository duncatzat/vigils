fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(INVOKE_COMMANDS)),
    )
    .expect("failed to run tauri-build");
}

include!("src/commands.rs");
