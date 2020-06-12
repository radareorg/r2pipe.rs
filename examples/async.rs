use r2pipe::R2Pipe;

use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;

const FILENAME: &'static str = "/bin/ls";

pub struct R2PipeAsync {
    tx: Sender<String>,
    rx: Receiver<String>,
    tx2: Sender<String>,
    rx2: Receiver<String>,
    cbs: Vec<Arc<dyn Fn(String)>>,
}

impl R2PipeAsync {
    pub fn open() -> R2PipeAsync {
        let (tx, rx) = channel(); // query
        let (tx2, rx2) = channel(); // result
        R2PipeAsync {
            tx: tx,
            rx: rx,
            tx2: tx2,
            rx2: rx2,
            cbs: Vec::new(),
        }
    }

    pub fn cmd(&mut self, str: &'static str, cb: Arc<dyn Fn(String)>) {
        self.cbs.insert(0, cb);
        self.tx.send(str.to_string()).unwrap();
    }

    pub fn quit(&mut self) {
        self.tx.send("q".to_string()).unwrap();
    }

    pub fn mainloop(mut self) {
        let child_rx = self.rx;
        let child_tx = self.tx2.clone();
        let child = thread::spawn(move || {
            let mut r2p = match R2Pipe::in_session() {
                Some(_) => R2Pipe::open(),
                None => R2Pipe::spawn(FILENAME.to_owned(), None),
            }
            .unwrap();
            loop {
                let msg = child_rx.recv().unwrap();
                if msg == "q" {
                    // push a result without callback
                    child_tx.send("".to_owned()).unwrap();
                    drop(child_tx);
                    break;
                }
                let res = r2p.cmd(&msg).unwrap();
                child_tx.send(res).unwrap();
            }
            r2p.close();
        });

        // main loop
        loop {
            let msg = self.rx2.recv();
            if msg.is_ok() {
                let res = msg.unwrap();
                if let Some(cb) = self.cbs.pop() {
                    cb(res.trim().to_string());
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        child.join().unwrap();
    }
}

fn main() {
    let mut r2pa = R2PipeAsync::open();
    r2pa.cmd(
        "?e One",
        Arc::new(|x| {
            println!("One: {}", x);
        }),
    );
    r2pa.cmd(
        "?e Two",
        Arc::new(|x| {
            println!("Two: {}", x);
        }),
    );
    r2pa.quit();
    r2pa.mainloop();
}
