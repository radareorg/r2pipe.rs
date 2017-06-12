// Copyright (c) 2015, The Radare Project. All rights reserved.
// See the COPYING file at the top-level directory of this distribution.
// Licensed under the BSD 3-Clause License:
// <http://opensource.org/licenses/BSD-3-Clause>
// This file may not be copied, modified, or distributed
// except according to those terms.

//! Basic structs for JSON encoding and decoding.

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LOpInfo {
    pub esil: Option<String>,
    pub offset: Option<u64>,
    pub opcode: Option<String>,
    pub optype: Option<String>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LFunctionInfo {
    pub addr: Option<u64>,
    pub name: Option<String>,
    pub ops: Option<Vec<LOpInfo>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LRegInfo {
    pub alias_info: Vec<LAliasInfo>,
    pub reg_info: Vec<LRegProfile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LAliasInfo {
    pub reg: String,
    pub role: u64,
    pub role_str: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LRegProfile {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub type_str: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LFlagInfo {
    pub offset: u64,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LBinInfo {
    pub core: Option<LCoreInfo>,
    pub bin: Option<LBin>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LCoreInfo {
    pub file: Option<String>,
    pub size: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LBin {
    pub arch: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub callrefs: Option<Vec<LCallInfo>>,
    pub calltype: Option<String>,
    pub codexrefs: Option<Vec<LCallInfo>>,
    pub datarefs: Option<Vec<u64>>,
    pub dataxrefs: Option<Vec<u64>>,
    pub name: Option<String>,
    pub offset: Option<u64>,
    pub realsz: Option<u64>,
    pub size: Option<u64>,
    pub ftype: Option<String>,
    pub locals: Option<Vec<LVarInfo>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LCallInfo {
    pub target: Option<u64>,
    pub call_type: Option<String>,
    pub source: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LSectionInfo {
    pub flags: Option<String>,
    pub name: Option<String>,
    pub paddr: Option<u64>,
    pub size: Option<u64>,
    pub vaddr: Option<u64>,
    pub vsize: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LVarInfo {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub vtype: Option<String>,
    pub reference: Option<LVarRef>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LVarRef {
    pub base: Option<String>,
    pub offset: Option<i64>,
}

impl_encode_decode!(for LReducedOpInfo, mapping { 
                                           offset: "offset",
                                           opcode: "opcode",
                                           optype: "type",
                                             size: "size" });

#[derive(Debug, Clone, Default)]
pub struct LReducedOpInfo {
    pub offset: Option<u64>,
    pub opcode: Option<String>,
    pub optype: Option<String>,
    pub size: Option<u64>,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Default)]
pub struct LGadgetInfo {
    pub opcodes: Option<Vec<LReducedOpInfo>>,
    pub retaddr: Option<u64>,
    pub size: Option<u64>,
}
