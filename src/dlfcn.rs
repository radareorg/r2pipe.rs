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

        // Prepare list of paths to try
        let mut lib_paths = vec![lib_name.clone()];

        // On Windows, add common radare2 installation paths
        if cfg!(windows) {
            // CI installs to C:\radare2\<version>\bin, where version changes
            // So we need to search for the latest version directory
            lib_paths.push(format!("C:\\radare2\\bin\\{}", lib_name));
            // Also try the versioned path pattern from CI
            if let Ok(entries) = std::fs::read_dir("C:\\radare2") {
                for entry in entries.flatten() {
                    if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                        let version_path = format!("{}\\bin\\{}", entry.path().display(), lib_name);
                        lib_paths.push(version_path);
                    }
                }
            }
        }

        // Try each path until we find one that works
        for lib_path in &lib_paths {
            if let Ok(lib) = unsafe { Library::new(lib_path) } {
                return Ok(LibHandle(Mutex::new(lib)));
            }
        }

        // If none worked, return the error from the first attempt
        Err(unsafe { Library::new(&lib_paths[0]) }.unwrap_err().into())
    }

    /// Load a symbol from the library and transmute it to the desired type.
    pub unsafe fn load_sym<T>(&mut self, name: &str) -> Result<T> {
        let lib = self.0.lock().unwrap();
        let sym: Symbol<T> = lib.get(name.as_bytes())?;
        Ok(std::mem::transmute_copy::<_, T>(&*sym))
    }
}
