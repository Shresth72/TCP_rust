use std::{
    io::{self, prelude::*},
    thread,
};

fn main() -> io::Result<()> {
    let mut i = tcp_rust::Interface::new()?;
    let mut listener = i.bind(8000)?;

    while let Ok(mut stream) = listener.accept() {
        eprintln!("got connection!");
        thread::spawn(move || {
            // stream.write(b"hello from rust-tcp!\n").unwrap();
            // stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);
                if n == 0 {
                    eprintln!("no more data!");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        });
    }

    Ok(())
}
