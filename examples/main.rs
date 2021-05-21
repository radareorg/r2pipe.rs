use serde_json;

use r2pipe::R2PipeSpawnOptions;
use r2pipe::{R2Pipe, Result};

fn test_trim() -> Result<()> {
    let mut ns = R2Pipe::spawn("/bin/ls".to_owned(), None)?;
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n")?);
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n")?);
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n")?);
    ns.close();
    Ok(())
}

fn main() -> Result<()> {
    test_trim()?;

    let opts = R2PipeSpawnOptions {
        exepath: "radare2".to_owned(),
        ..Default::default()
    };
    let mut r2p = match R2Pipe::in_session() {
        Some(_) => R2Pipe::open()?,
        None => R2Pipe::spawn("/bin/ls".to_owned(), Some(opts))?,
    };

    println!("{}", r2p.cmd("?e Hello World")?);

    let json = r2p.cmdj("ij")?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    println!("ARCH {}", json["bin"]["arch"]);
    println!("BITS {}", json["bin"]["bits"]);
    println!("Disasm:\n{}", r2p.cmd("pd 20")?);
    println!("Hexdump:\n{}", r2p.cmd("px 64")?);
    r2p.close();

    Ok(())
}
