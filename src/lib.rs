//! `R2Pipe` provides functions to interact with [radare2](http://rada.re/r/).
//! This aims to be a raw API. For more higher-level functions and structs to abstract
//! over the generated output, see [r2pipe.rs-frontend]().
//!
//! Hence this requires you to have radare2 installed on you system. For more
//! information refer to the r2 [repository](https://github.com/radare/radare2).
//! The module spawns an instance of r2 and communicates with it over pipes.
//! Using commands which produce a JSON output is recommended and easier to
//! parse.
//!
//! `R2Pipe`s are available for a several of languages. For more information
//! about r2pipes in general head over to the
//! [wiki](https://github.com/radare/radare2/wiki/R2PipeAPI).
//!
//! # Design
//! All the functionality for the crate are exposed through two structs:
//! `R2PipeLang` and `R2PipeSpawn`.
//!
//! Typically, there are two ways to invoke r2pipe. One by spawning a
//! child-process
//! from inside r2 and second by making the program spawn a child r2process.
//! `enum R2Pipe` is provided to allow easier use of the library and abstract
//! the
//! difference between these two methods.
//!
//! The `macro open_pipe!()` determines which of the two methods to use.
//!
//! **Note:** For the second method,
//! the path of the executable to be analyzed must be provided, while this is
//! implicit in the first (pass `None`) method (executable loaded by r2).
//!
//! # Example
//! ```no_run
//! #[macro_use]
//! extern crate r2pipe;
//! extern crate serde_json;
//! use r2pipe::R2Pipe;
//! fn main() {
//!     let path = Some("/bin/ls".to_owned());
//!     let mut r2p = open_pipe!(path).unwrap();
//!     println!("{}", r2p.cmd("?e Hello World").unwrap());
//!     if let Ok(json) = r2p.cmdj("ij") {
//!         println!("{}", serde_json::to_string_pretty(&json).unwrap());
//!         println!("ARCH {}", json["bin"]["arch"]);
//!     }
//!     r2p.close();
//! }
//! ```
//!
//! The crate offers various methods to interact with r2pipe, eg. via process (multi-threadable), http or tcp.
//! Check the examples/ dir for more complete examples.

#![doc(html_root_url = "https://radare.github.io/r2pipe.rs/")]

#[macro_use]
pub mod r2pipe;
pub mod r2;

// Rexport to bring it out one module.
pub use self::r2::R2;
pub use self::r2pipe::R2Pipe;
pub use self::r2pipe::R2PipeSpawnOptions;
