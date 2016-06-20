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

impl Default for R2 {
    fn default() -> R2 {
        R2::new::<&str>(None).expect("Unable to spawn r2 or find an open r2pipe")
    }
}

// fn send and recv allow users to send their own commands,
// i.e. The ones that are not currently abstracted by the R2 API.
// Ideally, all commonly used commands must be supported for easier use.
impl R2 {
    // TODO: Use an error type
    pub fn new<T: AsRef<str>>(path: Option<T>) -> Result<R2, String> {
        if path.is_none() && !R2::in_session() {
            let e = "No r2 session open. Please specify path!".to_owned();
            return Err(e);
        }

        // This means that path is `Some` or we have an open session.
        let pipe = open_pipe!(path.as_ref()).unwrap();
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
        self.analyze();
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
        let mut res = self.recv().replace("\n", "");
        if res.is_empty() {
            res = "{}".to_owned();
        }
        Json::from_str(&res).unwrap()
    }

    pub fn flush(&mut self) {
        self.readin = String::from("");
    }

    pub fn analyze(&mut self) {
        self.send("aaaaa");
        self.flush();
    }

    pub fn function(&mut self, func: &str) -> DecodeResult<LFunctionInfo> {
        let cmd = format!("pdfj @ {}", func);
        self.send(&cmd);
        let raw_json = self.recv();
        // Handle Error here.
        json::decode(&raw_json)
    }

    // get 'n' (or 16) instructions at 'offset' (or current position if offset in
    // `None`)
    pub fn insts(&mut self, n: Option<u64>, offset: Option<&str>) -> DecodeResult<Vec<LOpInfo>> {
        let n = n.unwrap_or(16);
        let offset: &str = offset.unwrap_or_default();
        let mut cmd = format!("pdj{}", n);
        if !offset.is_empty() {
            cmd = format!("{} @ {}", cmd, offset);
        }
        self.send(&cmd);
        let raw_json = self.recv();
        json::decode(&raw_json)
    }

    pub fn reg_info(&mut self) -> DecodeResult<LRegInfo> {
        self.send("drpj");
        let raw_json = self.recv();
        json::decode(&raw_json)
    }

    pub fn flag_info(&mut self) -> DecodeResult<Vec<LFlagInfo>> {
        self.send("fj");
        let raw_json = self.recv();
        json::decode(&raw_json)
    }

    pub fn bin_info(&mut self) -> DecodeResult<LBinInfo> {
        self.send("ij");
        let raw_json = self.recv();
        json::decode(&raw_json)
    }

    pub fn fn_list(&mut self) -> DecodeResult<Vec<FunctionInfo>> {
        self.send("aflj");
        let raw_json = self.recv();
        json::decode(&raw_json)
    }

    pub fn sections(&mut self) -> DecodeResult<Vec<LSectionInfo>> {
        self.send("Sj");
        json::decode(&self.recv())
    }
}
