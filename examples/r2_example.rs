extern crate r2pipe;
extern crate serde_json;

use r2pipe::r2::R2;

fn main() {
    let path = "/Users/sushant/projects/radare/rust/radeco-lib/ct1_sccp_ex.o";
    let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
    r2.init();
    println!("{}", serde_json::to_string(&r2.fn_list().expect("Failed to get Function data")).expect("Serialize failed"));
    //println!("{:#?}", r2.sections().expect("Failed to get section data"));
    println!("{:#?}", r2.fn_list().expect("Failed to get function data"));
    //println!("{:#?}", r2.flag_info().expect("Failed to get flag data"));
    //println!("{:#?}", r2.strings(true).expect("Failed to get strings data"));
    //println!("{:#?}", r2.strings(false).expect("Failed to get strings data"));
}
