#[macro_use] extern crate r2pipe;
extern crate rustc_serialize;

use r2pipe::r2::R2;
use rustc_serialize::json;

fn main() {
    let path = "/bin/ls";
    let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
    r2.init();
    println!("{}", json::encode(&r2.fn_list().expect("Failed to get Function data")).expect("Serialize failed"));
    println!("{:#?}", r2.sections().expect("Failed to get section data"));
    println!("{:#?}", r2.fn_list().expect("Failed to get function data"));
    println!("{:#?}", r2.flag_info().expect("Failed to get flag data"));
    println!("{:#?}", r2.strings(true).expect("Failed to get strings data"));
    println!("{:#?}", r2.strings(false).expect("Failed to get strings data"));
}
