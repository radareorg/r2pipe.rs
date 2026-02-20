use crate::Result;
use libloading::{Library, Symbol};
use std::sync::Mutex;

/// Contains a handle to the dynamically loaded library.
pub struct LibHandle(Mutex<Library>);

impl LibHandle {
    /// Load a shared library by name with platform-specific extension.
    pub fn new(name: &str, end: Option<&str>) -> Result<LibHandle> {
        let ext = if cfg!(windows) {
            ".dll"
        } else if cfg!(target_os = "macos") {
            ".dylib"
        } else {
            ".so"
        };
        let lib_name = format!("{}{}{}", name, ext, end.unwrap_or(""));
        let lib = unsafe { Library::new(&lib_name) }?;
        Ok(LibHandle(Mutex::new(lib)))
    }

    /// Load a symbol from the library and transmute it to the desired type.
    pub unsafe fn load_sym<T>(&mut self, name: &str) -> Result<T> {
        let lib = self.0.lock().unwrap();
        let sym: Symbol<T> = lib.get(name.as_bytes())?;
        Ok(std::mem::transmute_copy::<_, T>(&*sym))
    }
}
