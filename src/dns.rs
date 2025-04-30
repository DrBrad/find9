use std::{io, thread};
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::messages::message_base::MessageBase;

pub struct Dns {
    socket: UdpSocket
}

impl Dns {

    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;

        thread::spawn({
            let socket = socket.try_clone()?;

            move || {
                let mut buf = [0u8; 65535];

                loop {
                    match socket.recv_from(&mut buf) {
                        Ok((size, src_addr)) => {
                            match MessageBase::from_bytes(&buf, 0) {
                                Ok(message) => {
                                    println!("{:?}", message.to_bytes());


                                    socket.send_to(&message.to_bytes(), src_addr);
                                }
                                Err(_) => {}
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        _ => break
                    }
                }
            }
        });

        Ok(Self {
            socket
        })
    }

    pub fn close(&self) {
    }
}
