// Copyright (c) 2015, The Radare Project. All rights reserved.
// See the COPYING file at the top-level directory of this distribution.
// Licensed under the BSD 3-Clause License:
// <http://opensource.org/licenses/BSD-3-Clause>
// This file may not be copied, modified, or distributed
// except according to those terms.

//! Few functions for initialization, communication and termination of r2.
//!
//! If you wish to write wrappers for certain r2 functionalities,
//! contribute to the r2pipe.rs-frontend project. This aims to be a
//! barebones implementation of the pipe concept.

use crate::{r2pipe::R2Pipe, Error, Result};
use serde_json::Value;

pub struct R2 {
    pipe: R2Pipe,
    readin: String,
}

impl Default for R2 {
    fn default() -> R2 {
        R2::new::<&str>(None).expect("Unable to spawn r2 or find an open r2pipe")
    }
}

// fn send and recv allow users to send their own commands,
// i.e. The ones that are not currently abstracted by the R2 API.
// Ideally, all commonly used commands must be supported for easier use.
impl R2 {
    pub fn new<T: AsRef<str>>(path: Option<T>) -> Result<R2> {
        if path.is_none() && !R2::in_session() {
            return Err(Error::NoSession);
        }

        // This means that path is `Some` or we have an open session.
        let pipe = open_pipe!(path.as_ref())?;
        Ok(R2 {
            pipe,
            readin: String::new(),
        })
    }

    pub fn in_session() -> bool {
        R2Pipe::in_session().is_some()
    }

    pub fn from(r2p: R2Pipe) -> R2 {
        R2 {
            pipe: r2p,
            readin: String::new(),
        }
    }

    pub fn send(&mut self, cmd: &str) -> Result<()> {
        self.readin = self.pipe.cmd(cmd)?;
        Ok(())
    }

    pub fn recv(&mut self) -> String {
        let res = self.readin.clone();
        self.flush();
        res
    }

    pub fn recv_json(&mut self) -> Result<Value> {
        let mut res = self.recv().replace('\n', "");
        if res.is_empty() {
            res = "{}".to_owned();
        }

        Ok(serde_json::from_str(&res)?)
    }

    pub fn flush(&mut self) {
        self.readin = String::from("");
    }
}
