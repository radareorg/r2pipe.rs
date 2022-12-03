use libc::*;
//Conatins the lib
pub struct LibHandle(std::sync::Mutex<*mut c_void>);
