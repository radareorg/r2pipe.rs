extern crate r2pipe;
use r2pipe::R2Pipe;

use std::thread;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;

const FILENAME: &'static str = "/bin/ls";

pub struct R2PipeAsync {
	tx: Sender<String>,
	rx: Receiver<String>,
	tx2: Sender<String>,
	rx2: Receiver<String>,
	cbs: Vec<Arc<Fn(String)>>
}

impl R2PipeAsync {
	pub fn open() -> R2PipeAsync {
		let (tx, rx) = channel(); // query
		let (tx2, rx2) = channel(); // result
		R2PipeAsync {
			tx: tx, rx: rx,
			tx2: tx2, rx2: rx2,
			cbs: Vec::new()
		}
	}

	pub fn cmd(&mut self, str: &'static str, cb: &'static Fn(String)) {
		self.cbs.insert(0, Arc::new(cb));
		self.tx.send(str.to_string()).unwrap();
	}
	pub fn end(&mut self) {
		self.tx.send("q".to_string()).unwrap();
	}

	pub fn mainloop<'a>(mut self) {
		// XXX: cant borrow the receiver
		//let child_rx = &'a mut self.rx;
		let mut child_tx = self.tx2.clone();
		let child = thread::spawn(move|| {
			let mut r2p = match R2Pipe::in_session() {
				Some (_) => R2Pipe::open(),
				None => R2Pipe::spawn(FILENAME.to_owned())
			}.unwrap();
			loop {
				//let msg = self.rx.recv().unwrap();
				let msg = "pop";
				if msg == "q" {
					drop(child_tx);
					break;
				}
				let res = r2p.cmd(&msg).unwrap();
				child_tx.send(res).unwrap();
			}
			r2p.close();
		});

		/* main loop */
		loop {
			let r = self.rx2.recv();
			if r.is_err () {
				break;
			}
			let res = r.unwrap();

			println!("---> RES {}", res);
			let cb = self.cbs.pop().unwrap();
			cb (res);
		}
		child.join().unwrap();
	}
}

fn main() {
	let mut r2pa = R2PipeAsync::open ();
// XXX: cant pass the closure
/*
async.rs:79:21: 81:3 error: mismatched types:
 expected `&'static core::ops::Fn(collections::string::String) + 'static`,
    found `[closure@async.rs:79:21: 81:3]`

	r2pa.cmd("?e One", |x| {
		println!("One: {}", x);
	});
	r2pa.cmd("?e Two", |x| {
		println!("Two: {}", x);
	});
*/
	r2pa.mainloop();
}
