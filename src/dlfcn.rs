use crate::{Error, Result};
use libc::*;
//Conatins the lib
pub struct LibHandle(std::sync::Mutex<*mut c_void>);

fn to_cstr(s: &str) -> Result<*const c_char> {
    Ok(std::ffi::CString::new(s)
        .or_else(|_| Err(Error::LibError))?
        .into_raw())
}

fn free_cstr(ptr: *const c_char) {
    let _ = unsafe { std::ffi::CString::from_raw(ptr as *mut _) };
}

impl LibHandle {
    pub fn new(name: &str) -> Result<LibHandle> {
        let name = to_cstr(&format!(
            "{}{}",
            name,
            if cfg!(windows) {
                ".dll"
            } else if cfg!(macos) {
                ".dylib"
            } else {
                ".so"
            }
        ))?;
        let ret = unsafe { dlopen(name, RTLD_LAZY) };
        free_cstr(name);
        if ret.is_null() {
            Err(Error::LibError)
        } else {
            Ok(LibHandle(std::sync::Mutex::new(ret)))
        }
    }
    pub fn load_sym<T>(&mut self, name: &str) -> T {
        todo!();
    }
}

impl Drop for LibHandle {
    fn drop(&mut self) {
        let handle = *self.0.lock().unwrap();
        unsafe { libc::dlclose(handle) };
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn load_test() {
        let _lib = super::LibHandle::new("libr_core").unwrap();
    }
}
