use std::unicode;
use std::env;

trait R2Pipe {
	fn open(&self) -> R2Pipe;
}

fn main() {
	let fdin = std::env::var("R2PIPE_IN");
	println!("Hello World {}", fdin);
	//r2 := R2Pipe.open ();
	//r2.cmd ();
}

/*
struct R2PipeData {
	width: int
}

impl R2Pipe for R2PipeData {
	fn area 
}

public class R2Pipe {
	public static void main() {
	}
}
*/
