use serde_json;

use r2pipe::{R2Pipe, Result};

fn main() -> Result<()> {
    let mut r2p = R2Pipe::tcp("localhost:9080")?;

    println!("{}", r2p.cmd("?e Hello World")?);

    let json = r2p.cmdj("ij")?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    println!("ARCH {}", json["bin"]["arch"]);
    println!("BITS {}", json["bin"]["bits"]);
    println!("Disasm:\n{}", r2p.cmd("pd 20")?);
    println!("Hexdump:\n{}", r2p.cmd("px 64")?);

    Ok(())
}
