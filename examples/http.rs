use r2pipe::Result;

fn main() -> Result<()> {
    #[cfg(feature = "http")]
    {
        use r2pipe::R2Pipe;
        use serde_json;

        let mut r2p = R2Pipe::http("http://localhost:9080")?;

        let json = r2p.cmdj("ij")?;
        println!("{}", serde_json::to_string_pretty(&json)?);
        println!("ARCH {}", json["bin"]["arch"]);
        println!("BITS {}", json["bin"]["bits"]);
        println!("Disasm:\n{}", r2p.cmd("pd 20")?);
        println!("Hexdump:\n{}", r2p.cmd("px 64")?);
    }

    Ok(())
}
