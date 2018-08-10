//! Provides functionality to connect with radare2.
//!
//! Please check crate level documentation for more details and example.

use reqwest;

use libc;
use std::process::Command;
use std::process::Stdio;
use std::process;
use std::env;
use std::str;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::{TcpStream, ToSocketAddrs, SocketAddr};

use serde_json;
use serde_json::Value;
use serde_json::Error;

/// File descriptors to the parent r2 process.
pub struct R2PipeLang {
    read: BufReader<File>,
    write: File,
}

/// Stores descriptors to the spawned r2 process.
pub struct R2PipeSpawn {
    read: BufReader<process::ChildStdout>,
    write: process::ChildStdin,
}

/// Stores the socket address of the r2 process.
pub struct R2PipeTcp {
    socket_addr: SocketAddr,
}

pub struct R2PipeHttp {
    host: String,
}

#[derive(Default)]
pub struct R2PipeSpawnOptions {
    pub exepath: String,
    pub args: Vec<&'static str>,
}

/// Provides abstraction between the three invocation methods.
pub enum R2Pipe {
    Pipe(R2PipeSpawn),
    Lang(R2PipeLang),
    Tcp(R2PipeTcp),
    Http(R2PipeHttp),
}

fn atoi(k: &str) -> i32 {
    match k.parse::<i32>() {
        Ok(val) => val,
        Err(_) => -1,
    }
}

fn getenv(k: &str) -> i32 {
    match env::var(k) {
        Ok(val) => atoi(&val),
        Err(_) => -1,
    }
}

fn process_result(res: Vec<u8>) -> Result<String, String> {
    let len = res.len();
    let out = if len > 0 {
        let res_without_zero = &res[..len - 1];
        if let Ok(utf8str) = str::from_utf8(res_without_zero) {
            String::from(utf8str.trim())
        } else {
            return Err("Failed".to_owned());
        }
    } else {
        "".to_owned()
    };
    Ok(out)
}

#[macro_export]
macro_rules! open_pipe {
	() => {
            R2Pipe::open(),
        };
	($x: expr) => {
		match $x {
			Some(path) => R2Pipe::spawn(path, None),
			None => R2Pipe::open(),
		}
	};
	($x: expr, $y: expr) => {
		match $x $y {
			Some(path, opts) => R2Pipe::spawn(path, opts),
			(None, None) => R2Pipe::open(),
		}
	}
}

impl R2Pipe {
    #[cfg(not(windows))]
    pub fn open() -> Result<R2Pipe, &'static str> {
        use std::os::unix::io::FromRawFd;

        let (f_in, f_out) = match R2Pipe::in_session() {
            Some(x) => x,
            None => return Err("Pipe not open. Please run from r2"),
        };
        let res = unsafe {
            // dup file descriptors to avoid from_raw_fd ownership issue
            let (d_in, d_out) = (libc::dup(f_in), libc::dup(f_out));
            R2PipeLang {
                read: BufReader::new(File::from_raw_fd(d_in)),
                write: File::from_raw_fd(d_out),
            }
        };
        Ok(R2Pipe::Lang(res))
    }

    #[cfg(windows)]
    pub fn open() -> Result<R2Pipe, &'static str> {
        Err("`open()` is not yet supported on windows")
    }

    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        match *self {
            R2Pipe::Pipe(ref mut x) => x.cmd(cmd.trim()),
            R2Pipe::Lang(ref mut x) => x.cmd(cmd.trim()),
            R2Pipe::Tcp(ref mut x) => x.cmd(cmd.trim()),
            R2Pipe::Http(ref mut x) => x.cmd(cmd.trim()),
        }
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        match *self {
            R2Pipe::Pipe(ref mut x) => x.cmdj(cmd.trim()),
            R2Pipe::Lang(ref mut x) => x.cmdj(cmd.trim()),
            R2Pipe::Tcp(ref mut x) => x.cmdj(cmd.trim()),
            R2Pipe::Http(ref mut x) => x.cmdj(cmd.trim()),
        }
    }

    pub fn close(&mut self) {
        match *self {
            R2Pipe::Pipe(ref mut x) => x.close(),
            R2Pipe::Lang(ref mut x) => x.close(),
            R2Pipe::Tcp(ref mut x) => x.close(),
            R2Pipe::Http(ref mut x) => x.close(),
        }
    }

    pub fn in_session() -> Option<(i32, i32)> {
        let f_in = getenv("R2PIPE_IN");
        let f_out = getenv("R2PIPE_OUT");
        if f_in < 0 || f_out < 0 {
            return None;
        }
        Some((f_in, f_out))
    }

    #[cfg(windows)]
    pub fn in_windows_session() -> Option<String> {
        match env::var("R2PIPE_PATH") {
            Ok(val) => Some(format!("\\\\.\\pipe\\{}", val)),
            Err(_) => None,
        }
    }

    /// Creates a new R2PipeSpawn.
    pub fn spawn<T: AsRef<str>>(name: T, opts: Option<R2PipeSpawnOptions>) -> Result<R2Pipe, &'static str> {
        if name.as_ref() == "" {
            if let Some(_) = R2Pipe::in_session() {
                return R2Pipe::open();
            }
        }

        let exepath = match opts {
            Some(ref opt) => opt.exepath.clone(),
            _ => "r2".to_owned(),
        };
        let args = match opts {
            Some(ref opt) => opt.args.clone(),
            _ => vec![],
        };
        let path = Path::new(name.as_ref());
        let child = match Command::new(exepath)
            .arg("-q0")
            .args(&args)
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn() {
            Ok(c) => c,
            Err(_) => return Err("Unable to spawn r2."),
        };

        let sin = child.stdin.unwrap();
        let mut sout = child.stdout.unwrap();

        // flush out the initial null byte.
        let mut w = [0; 1];
        sout.read(&mut w).unwrap();

        let res = R2PipeSpawn {
            read: BufReader::new(sout),
            write: sin,
        };

        Ok(R2Pipe::Pipe(res))
    }

    /// Creates a new R2PipeTcp
    pub fn tcp<A: ToSocketAddrs>(addr: A) -> Result<R2Pipe, &'static str> {
        // use `connect` to figure out which socket address works
        let stream = try!(TcpStream::connect(addr).map_err(|_| "Unable to connect TCP stream"));
        let addr = try!(stream.peer_addr().map_err(|_| "Unable to get peer address"));
        Ok(R2Pipe::Tcp(R2PipeTcp { socket_addr: addr }))
    }

    /// Creates a new R2PipeHttp
    pub fn http(host: &str) -> Result<R2Pipe, &'static str> {
        Ok(R2Pipe::Http(R2PipeHttp { host: host.to_string() }))
    }
}

impl R2PipeSpawn {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        let cmd_ = cmd.to_owned() + "\n";
        if let Err(e) = self.write.write(cmd_.as_bytes()) {
            return Err(e.to_string());
        }

        let mut res: Vec<u8> = Vec::new();
        if let Err(e) = self.read.read_until(0u8, &mut res) {
            return Err(e.to_string());
        }
        process_result(res)
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        if let Ok(res) = self.cmd(cmd) {
            if res == "" {
                return Err("Empty JSON".to_string());
            }

            let v: Result<Value, Error> = serde_json::from_str(&res);
            if v.is_ok() {
                Ok(v.unwrap())
            } else {
                v.map_err(|e| e.to_string())
            }
        } else {
            Err("oops cmd".to_string())
        }
    }

    pub fn close(&mut self) {
        let _ = self.cmd("q!");
    }
}

impl R2PipeLang {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        self.write.write(cmd.as_bytes()).unwrap();
        let mut res: Vec<u8> = Vec::new();
        self.read.read_until(0u8, &mut res).unwrap();
        process_result(res)
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        let res = try!(self.cmd(cmd));

        let v: Result<Value, Error> = serde_json::from_str(&res);
        if v.is_ok() {
            Ok(v.unwrap())
        } else {
            v.map_err(|e| e.to_string())
        }
    }

    pub fn close(&mut self) {
        // self.read.close();
        // self.write.close();
    }
}

impl R2PipeHttp {

    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        let url = format!("http://{}/cmd/{}", self.host, cmd);
        let res = reqwest::get(&url).unwrap();
        let bytes = res.bytes()
            .into_iter()
            .filter_map(|e| e.ok())
            .collect::<Vec<_>>();
        str::from_utf8(bytes.as_slice())
            .map(|s| s.to_string())
            .map_err(|err| err.to_string())
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value ,String> {
        let res = try!(self.cmd(cmd));
        serde_json::from_str(&res)
            .map_err(|e| format!("Unable to parse json: {}", e))
    }

    pub fn close(&mut self) {}
}

impl R2PipeTcp {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        let mut stream = try!(TcpStream::connect(self.socket_addr)
                              .map_err(|e| format!("Unable to connect TCP stream: {}", e)));
        try!(stream.write_all(cmd.as_bytes())
             .map_err(|e| format!("Unable to write to TCP stream: {}", e)));
        let mut res: Vec<u8> = Vec::new();
        try!(stream.read_to_end(&mut res)
             .map_err(|e| format!("Unable to read from TCP stream: {}", e)));
        res.push(0);
        process_result(res)
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        let res = try!(self.cmd(cmd));
        serde_json::from_str(&res).map_err(|e| format!("Unable to parse json: {}", e))
    }

    pub fn close(&mut self) {}
}
