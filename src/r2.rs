// Copyright (c) 2015, The Radare Project. All rights reserved.
// See the COPYING file at the top-level directory of this distribution.
// Licensed under the BSD 3-Clause License:
// <http://opensource.org/licenses/BSD-3-Clause>
// This file may not be copied, modified, or distributed
// except according to those terms.

//! `R2` struct to make interaction with r2 easier
//!
//! This module is for convenience purposes. It provides a nicer way to
//! interact with r2 by
//! parsing the JSON into structs. Note that all commands are not supported and
//! this
//! module is updated only on a need basis. r2 commands that are not supported
//! by this module can
//! still be called by using the send() and recv() that `R2` provides. If this
//! is a command that
//! you see yourself using frequently and feel it is important to have nice
//! rust wrappers
//! feel free to raise an issue, or better yet a pull request implementing the
//! same.

use r2pipe::R2Pipe;
use rustc_serialize::json::{DecodeResult, Json};
use rustc_serialize::json;

use super::structs::*;

pub struct R2 {
    pipe: R2Pipe,
    readin: String,
}

// fn send and recv allow users to send their own commands,
// i.e. The ones that are not currently abstracted by the R2 API.
// Ideally, all commonly used commands must be supported for easier use.
impl R2 {
    // TODO: Use an error type
    pub fn new(path: Option<String>) -> Result<R2, String> {
        if path.is_none() && !R2::in_session() {
            let e = "No r2 session open. Please specify path!".to_owned();
            return Err(e);
        }

        // This means that path is `Some` or we have an open session.
        let pipe = open_pipe!(path).unwrap();
        Ok(R2 {
            pipe: pipe,
            readin: String::new(),
        })
    }

    pub fn in_session() -> bool {
        match R2Pipe::in_session() {
            Some(_) => true,
            None => false,
        }
    }

    pub fn from(r2p: R2Pipe) -> R2 {
        R2 {
            pipe: r2p,
            readin: String::new(),
        }
    }

    // Does some basic configurations (sane defaults).
    pub fn init(&mut self) {
        self.send("e asm.esil = true");
        self.send("e scr.color = false");
        self.send("aaa");
        self.flush();
    }

    pub fn close(&mut self) {
        self.send("q!");
    }

    pub fn send(&mut self, cmd: &str) {
        self.readin = self.pipe.cmd(cmd).unwrap();
    }

    pub fn recv(&mut self) -> String {
        let res = self.readin.clone();
        self.flush();
        res
    }

    pub fn recv_json(&mut self) -> Json {
        let res = self.recv().replace("\n", "");
        Json::from_str(&*res).unwrap()
    }

    pub fn flush(&mut self) {
        self.readin = String::from("");
    }

    pub fn analyze(&mut self) {
        self.send("aa");
        self.flush();
    }

    pub fn get_function(&mut self, func: &str) -> DecodeResult<LFunctionInfo> {
        let cmd = format!("pdfj @ {}", func);
        self.send(&*cmd);
        let raw_json = self.recv();
        // Handle Error here.
        json::decode(&*raw_json)
    }

    // get 'n' (or 16) instructions at 'offset' (or current position if offset in
    // `None`)
    pub fn get_insts(&mut self,
                     n: Option<u64>,
                     offset: Option<&str>)
                     -> DecodeResult<Vec<LOpInfo>> {
        let n = n.unwrap_or(16);
        let offset: &str = offset.unwrap_or_default();
        let mut cmd = format!("pdj{}", n);
        if offset.len() > 0 {
            cmd = format!("{} @ {}", cmd, offset);
        }
        self.send(&*cmd);
        let raw_json = self.recv();
        json::decode(&*raw_json)
    }

    pub fn get_reg_info(&mut self) -> DecodeResult<LRegInfo> {
        self.send("drpj");
        let raw_json = self.recv();
        json::decode(&*raw_json)
    }

    pub fn get_flag_info(&mut self) -> DecodeResult<Vec<LFlagInfo>> {
        self.send("fj");
        let raw_json = self.recv();
        json::decode(&*raw_json)
    }

    pub fn get_bin_info(&mut self) -> DecodeResult<LBinInfo> {
        self.send("ij");
        let raw_json = self.recv();
        json::decode(&*raw_json)
    }

    pub fn get_fn_list(&mut self) -> Json {
        self.send("aflj");
        self.recv_json()
    }
}
