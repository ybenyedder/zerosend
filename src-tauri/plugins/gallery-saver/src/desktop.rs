use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

/// No-op on desktop: platforms other than Android already save received files
/// straight into a normal, user-visible folder, so there is nothing to bridge
/// into a media library here.
pub struct GallerySaver<R: Runtime>(std::marker::PhantomData<R>);

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<GallerySaver<R>> {
    Ok(GallerySaver(std::marker::PhantomData))
}

impl<R: Runtime> GallerySaver<R> {
    pub fn save(&self, _path: &str, _name: &str, _mime: &str) -> crate::Result<()> {
        Ok(())
    }
}
