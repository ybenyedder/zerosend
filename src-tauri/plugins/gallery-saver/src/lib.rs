use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
use android as platform;

#[cfg(not(target_os = "android"))]
mod desktop;
#[cfg(not(target_os = "android"))]
use desktop as platform;

pub use platform::GallerySaver;

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub trait GallerySaverExt<R: Runtime> {
    fn gallery_saver(&self) -> &GallerySaver<R>;
}

impl<R: Runtime, T: Manager<R>> GallerySaverExt<R> for T {
    fn gallery_saver(&self) -> &GallerySaver<R> {
        self.state::<GallerySaver<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("gallery-saver")
        .setup(|app, api| {
            let gallery_saver = platform::init(app, api)?;
            app.manage(gallery_saver);
            Ok(())
        })
        .build()
}
