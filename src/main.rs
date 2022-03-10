use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:5890")?;

    let mut rec_streams: Vec<TcpStream> = Vec::new();

    // accept connections and process them serially
    for stream in listener.incoming() {
        let mut unstream = stream?;

        let mut hbuf = [0u8];
        unstream.read(&mut hbuf).unwrap();

        match hbuf[0] {
            0b00001111 => {
                let mut nbuf = [0u8];
                unstream.read(&mut nbuf).unwrap();
                let mut sign_buf = [0u8; 256];
                unstream.read(&mut sign_buf).unwrap();
                let mut pubkey_buf = [0u8; 294];
                unstream.read(&mut pubkey_buf).unwrap();

                let mut msg_buf: Vec<u8> = Vec::new();

                let mut buf = [0u8];

                for _ in 0..nbuf[0] {
                    unstream.read(&mut buf).unwrap();
                    msg_buf.push(buf[0]);
                }

                let keypair = PKey::public_key_from_der(&pubkey_buf).unwrap();

                let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
                verifier.update(&msg_buf).unwrap();

                if !verifier.verify(&sign_buf).unwrap() {
                    continue;
                }

                let message = [
                    &[msg_buf.len() as u8][..],
                    &sign_buf[..],
                    &pubkey_buf[..],
                    &msg_buf[..],
                ]
                .concat();

                let mut to_rem: Vec<usize> = Vec::new();

                for (i, mut rec) in rec_streams.iter().enumerate() {
                    match rec.write_all(&message) {
                        Ok(t) => t,
                        Err(_) => {
                            to_rem.push(i);
                        }
                    }
                }

                for i in to_rem {
                    rec_streams.remove(i);
                }
            }
            0b11110000 => {
                rec_streams.push(unstream);
            }
            _ => {},
        }
    }
    Ok(())
}
