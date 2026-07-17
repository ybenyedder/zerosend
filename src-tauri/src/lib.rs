mod client;
mod commands;
mod discovery;
mod identity;
mod mtls;
mod pinning;
mod server;
mod state;
mod tls;
mod trust;
mod types;

use state::AppState;
use std::sync::Arc;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Both axum-server (receiving) and reqwest (sending) link rustls; with two
    // crypto backends available in the dependency graph, rustls refuses to guess
    // which one to use unless we pick one explicitly, once, up front.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init());

    #[cfg(target_os = "android")]
    {
        builder = builder.plugin(tauri_plugin_gallery_saver::init());
    }

    builder
        .setup(|app| {
            let app_state = Arc::new(AppState::new(app.handle().clone()));
            app.manage(app_state.clone());

            tauri::async_runtime::spawn(async move {
                server::spawn(app_state.clone()).await;
                discovery::spawn(app_state);
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_device,
            commands::list_peers,
            commands::get_settings,
            commands::update_settings,
            commands::send_files_to_peer,
            commands::respond_to_transfer,
            commands::list_trusted_peers,
            commands::forget_peer,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
