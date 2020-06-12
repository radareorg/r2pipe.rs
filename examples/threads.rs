use r2pipe::R2Pipe;

fn main() {
    // Lets spawn some r2pipes to open some binaries
    // First two arguments for R2Pipe::threads() are the same as for R2Pipe::spawn() but inside vectors
    // Third and last argument is an option of a callback function
    let pipes = match R2Pipe::threads(
        vec!["/bin/ls", "/bin/id", "/bin/cat"],
        vec![None, None, None],
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            println!("Error spawning Pipes: {}", e);
            return;
        }
    };

    // At this point we can iter through all of our r2pipes and send some commands
    for p in pipes.iter() {
        if let Ok(_) = p.send("ij".to_string()) {};
    }

    // do_other_stuff_here();

    // Lets iter again and see what the pipes got
    for p in pipes.iter() {
        // this will block, do "p.recv(false)" for non-blocking receive inside a loop
        if let Ok(msg) = p.recv(true) {
            println!("Pipe #{} says: {}", p.id, msg);
        }
    }

    // Finally properly close all pipes
    // Note: For "join()" we need to borrow so pipes.iter() won't work for this
    for p in pipes {
        if let Ok(_) = p.send("q".to_string()) {};
        p.handle.join().unwrap();
    }
}
