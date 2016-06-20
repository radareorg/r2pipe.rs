// Copyright (c) 2015, The Radare Project. All rights reserved.
// See the COPYING file at the top-level directory of this distribution.
// Licensed under the BSD 3-Clause License:
// <http://opensource.org/licenses/BSD-3-Clause>
// This file may not be copied, modified, or distributed
// except according to those terms.

//! Basic structs for JSON encoding and decoding.
use rustc_serialize::{Decodable, Decoder};

macro_rules! impl_decode {
    (for $st:ident, mapping { $($internal:ident: $external:expr),* }) => {
        impl Decodable for $st {
            fn decode<D: Decoder>(d: &mut D) -> Result<$st, D::Error> {
                d.read_struct("root", 0, |dd| {
                        let decoded = $st {
                            $(
                                $internal: dd.read_struct_field($external, 0, |d| Decodable::decode(d)).ok(),
                            )*
                        };
                        Ok(decoded)
                    })
            }
        }
    }
}

impl_decode!(for LOpInfo, mapping {   esil: "esil",
                                    offset: "offset",
                                    opcode: "opcode",
                                    optype: "type",
                                      size: "size" });

#[derive(RustcEncodable, Debug, Clone, Default)]
pub struct LOpInfo {
    pub esil: Option<String>,
    pub offset: Option<u64>,
    pub opcode: Option<String>,
    pub optype: Option<String>,
    pub size: Option<u64>,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LFunctionInfo {
    pub addr: Option<u64>,
    pub name: Option<String>,
    pub ops: Option<Vec<LOpInfo>>,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LRegInfo {
    pub alias_info: Vec<LAliasInfo>,
    pub reg_info: Vec<LRegProfile>,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LAliasInfo {
    pub reg: String,
    pub role: u64,
    pub role_str: String,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LRegProfile {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub type_str: String,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LFlagInfo {
    pub offset: u64,
    pub name: String,
    pub size: u64,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LBinInfo {
    pub core: Option<LCoreInfo>,
    pub bin: Option<LBin>,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LCoreInfo {
    pub file: Option<String>,
    pub size: Option<usize>,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LBin {
    pub arch: Option<String>,
}

impl_decode!(for FunctionInfo, mapping {  callrefs: "callrefs",
                                          calltype: "calltype",
                                         codexrefs: "codexrefs",
                                          datarefs: "datarefs",
                                         dataxrefs: "dataxrefs",
                                              name: "name",
                                            offset: "offset",
                                            realsz: "realsz",
                                              size: "size",
                                             ftype: "type" });
#[derive(RustcEncodable, Debug, Clone, Default)]
pub struct FunctionInfo {
    pub callrefs: Option<Vec<LCallInfo>>,
    pub calltype: Option<String>,
    pub codexrefs: Option<Vec<u64>>,
    pub datarefs: Option<Vec<u64>>,
    pub dataxrefs: Option<Vec<u64>>,
    pub name: Option<String>,
    pub offset: Option<u64>,
    pub realsz: Option<u64>,
    pub size: Option<u64>,
    pub ftype: Option<String>,
}

impl_decode!(for LCallInfo, mapping { addr: "addr", call_type: "type" });
#[derive(RustcEncodable, Debug, Clone, Default)]
pub struct LCallInfo {
    pub addr: Option<u64>,
    pub call_type: Option<String>,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LSectionInfo {
    pub flags: Option<String>,
    pub name: Option<String>,
    pub paddr: Option<u64>,
    pub size: Option<u64>,
    pub vaddr: Option<u64>,
    pub vsize: Option<u64>,
}

impl_decode!(for LStringInfo, mapping {  length: "length",
                                        ordinal: "ordinal",
                                          paddr: "paddr",
                                        section: "section",
                                           size: "size",
                                         string: "string",
                                          vaddr: "vaddr",
                                          stype: "type" });
#[derive(RustcEncodable, Debug, Clone, Default)]
pub struct LStringInfo {
    pub length: Option<u64>,
    pub ordinal: Option<u64>,
    pub paddr: Option<u64>,
    pub section: Option<String>,
    pub size: Option<u64>,
    pub string: Option<String>,
    pub vaddr: Option<u64>,
    pub stype: Option<String>,
}
