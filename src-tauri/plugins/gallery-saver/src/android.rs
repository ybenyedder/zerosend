use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

const PLUGIN_IDENTIFIER: &str = "app.zerosend.gallerysaver";

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<GallerySaver<R>> {
    let handle = api
        .register_android_plugin(PLUGIN_IDENTIFIER, "GallerySaverPlugin")
        .map_err(|e| crate::Error(e.to_string()))?;
    Ok(GallerySaver(handle))
}

pub struct GallerySaver<R: Runtime>(PluginHandle<R>);

#[derive(Serialize)]
struct SaveArgs<'a> {
    path: &'a str,
    name: &'a str,
    mime: &'a str,
}

#[derive(Deserialize)]
struct SaveResponse {
    #[allow(dead_code)]
    uri: Option<String>,
}

impl<R: Runtime> GallerySaver<R> {
    /// Copies the file at `path` into the appropriate MediaStore collection
    /// (Pictures/Movies/Downloads, under a "ZeroSend" subfolder) so it shows up
    /// in the Gallery/Files apps, then deletes the source file. `path` must be
    /// a plain filesystem path the app already owns (its own cache/staging file),
    /// not a content:// URI.
    pub fn save(&self, path: &str, name: &str, mime: &str) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<SaveResponse>("save", SaveArgs { path, name, mime })
            .map(|_| ())
            .map_err(|e| crate::Error(e.to_string()))
    }
}
