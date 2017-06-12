#[macro_use]
extern crate r2pipe;
extern crate rustc_serialize;

use r2pipe::r2::R2;
use rustc_serialize::json;

fn main() {
    let path = "/bin/ls";
    let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
    r2.init();
    r2.set_config_var("search", "from", "4267592");
    println!("{}", json::encode(&r2.rop_gadgets_by_string("pop rbx").expect("Failed to get Rop gadget data")).expect("Serialize failed."));
}
