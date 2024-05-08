use std::{
    io::{self, prelude::*},
    thread,
};

fn main() -> io::Result<()> {
    let mut i = tcp_rust::Interface::new()?;
    let mut l1 = i.bind(9000)?;
    let mut l2 = i.bind(9001)?;

    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection! on {}", 9000);

            let n = stream.read(&mut [0]).unwrap();
            eprintln!("read data");
            // atleast detect when there's no more data
            assert_eq!(n, 0);

            eprintln!("no more data!");
        }
    });

    let jh2 = thread::spawn(move || {
        while let Ok(_stream) = l2.accept() {
            eprintln!("got connection! on {}", 9001);
        }
    });

    jh1.join().unwrap();
    jh2.join().unwrap();

    Ok(())
}
