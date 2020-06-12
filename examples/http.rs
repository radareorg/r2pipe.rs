use serde_json;

use r2pipe::R2Pipe;

fn main() {
    let mut r2p = R2Pipe::http("http://localhost:9080").unwrap();

    let json = r2p.cmdj("ij").unwrap();
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
    println!("ARCH {}", json["bin"]["arch"]);
    println!("BITS {}", json["bin"]["bits"]);
    println!("Disasm:\n{}", r2p.cmd("pd 20").unwrap());
    println!("Hexdump:\n{}", r2p.cmd("px 64").unwrap());
    r2p.close();
}
