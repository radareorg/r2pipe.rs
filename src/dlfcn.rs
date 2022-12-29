use crate::{Error, Result};
use libc::*;

// Contains a handle to the library.
pub struct LibHandle(std::sync::Mutex<*mut c_void>);

pub fn to_cstr(s: &str) -> Result<*const c_char> {
    Ok(std::ffi::CString::new(s)
        .map_err(|_| Error::SharedLibraryLoadError)?
        .into_raw())
}

pub fn free_cstr(ptr: *const c_char) {
    let _ = unsafe { std::ffi::CString::from_raw(ptr as *mut _) };
}

impl LibHandle {
    pub fn new(name: &str, end: Option<&str>) -> Result<LibHandle> {
        let name = to_cstr(&format!(
            "{}{}{}",
            name,
            if cfg!(windows) {
                ".dll"
            } else if cfg!(macos) {
                ".dylib"
            } else {
                ".so"
            },
            end.unwrap_or("")
        ))?;
        let ret = unsafe { dlopen(name, RTLD_LAZY) };
        free_cstr(name);
        if ret.is_null() {
            Err(Error::SharedLibraryLoadError)
        } else {
            Ok(LibHandle(std::sync::Mutex::new(ret)))
        }
    }

    pub unsafe fn load_sym<T>(&mut self, name: &str) -> Result<T> {
        let handle = *self.0.lock().unwrap();
        let name = to_cstr(name)?;
        let sym = dlsym(handle, name);
        free_cstr(name);
        if sym.is_null() {
            Err(Error::SharedLibraryLoadError)
        } else {
            Ok(std::mem::transmute_copy(&sym))
        }
    }
}

impl Drop for LibHandle {
    fn drop(&mut self) {
        let handle = *self.0.lock().unwrap();
        // In some cases, dlclose is not required to do anything. We allow it
        // to silently fail.
        let _ = unsafe { libc::dlclose(handle) };
    }
}
