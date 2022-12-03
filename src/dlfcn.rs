use crate::{Error, Result};
use libc::*;
//Conatins the lib
pub struct LibHandle(std::sync::Mutex<*mut c_void>);

pub fn to_cstr(s: &str) -> Result<*const c_char> {
    Ok(std::ffi::CString::new(s)
        .or_else(|_| Err(Error::LibError))?
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
            Err(Error::LibError)
        } else {
            Ok(LibHandle(std::sync::Mutex::new(ret)))
        }
    }
    pub fn load_sym<T>(&mut self, name: &str) -> Result<T> {
        let handle = *self.0.lock().unwrap();
        let name = to_cstr(name)?;
        let sym = unsafe { dlsym(handle, name) };
        free_cstr(name);
        if sym.is_null() {
            Err(Error::LibError)
        } else {
            Ok(unsafe { std::mem::transmute_copy(&sym) })
        }
    }
}

impl Drop for LibHandle {
    fn drop(&mut self) {
        let handle = *self.0.lock().unwrap();
        let ret = unsafe { libc::dlclose(handle) };
        if ret != 0 {
            panic!("Failed to close the lib");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn load_lib_test() {
        let mut _lib = super::LibHandle::new("libc", Some(".6")).unwrap();
    }
    #[test]
    fn load_sym_test() {
        let mut lib = super::LibHandle::new("libm", Some(".6")).unwrap();
        let sqrt: fn(libc::c_double) -> libc::c_double = lib.load_sym("sqrt").unwrap();
        assert_eq!(sqrt(4.0), 2.0);
    }
}
