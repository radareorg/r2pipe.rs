use serde_json;

use r2pipe::R2Pipe;
use r2pipe::R2PipeSpawnOptions;

fn test_trim() {
    let mut ns = R2Pipe::spawn("/bin/ls".to_owned(), None).unwrap();
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n").unwrap());
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n").unwrap());
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n").unwrap());
    ns.close();
    //    process::exit(0);
}

fn main() {
    test_trim();

    // let mut r2p = open_pipe!().unwrap();
    let opts = R2PipeSpawnOptions {
        exepath: "radare2".to_owned(),
        ..Default::default()
    };
    let mut r2p = match R2Pipe::in_session() {
        Some(_) => R2Pipe::open(),
        None => R2Pipe::spawn("/bin/ls".to_owned(), Some(opts)),
    }
    .unwrap();

    println!("{}", r2p.cmd("?e Hello World").unwrap());

    let json = r2p.cmdj("ij").unwrap();
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
    println!("ARCH {}", json["bin"]["arch"]);
    println!("BITS {}", json["bin"]["bits"]);
    println!("Disasm:\n{}", r2p.cmd("pd 20").unwrap());
    println!("Hexdump:\n{}", r2p.cmd("px 64").unwrap());
    r2p.close();
}
