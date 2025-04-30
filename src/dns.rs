use std::{io, thread};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::messages::message_base::MessageBase;
use crate::records::a_record;
use crate::records::a_record::ARecord;

pub struct Dns {
    server: Option<UdpSocket>,
    running: Arc<AtomicBool>
}

impl Dns {

    pub fn new() -> Self {
        Self {
            server: None,
            running: Arc::new(AtomicBool::new(false))
        }
    }

    pub fn start(&mut self, port: u16) -> io::Result<()> {
        if self.is_running() {
            return Err(io::Error::new(io::ErrorKind::Other, "Server is already running"));
        }

        self.running.store(true, Ordering::Relaxed);

        self.server = Some(UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?);

        thread::spawn({
            let server = self.server.as_ref().unwrap().try_clone()?;
            let running = Arc::clone(&self.running);
            move || {
                let mut buf = [0u8; 65535];

                while running.load(Ordering::Relaxed) {
                    match server.recv_from(&mut buf) {
                        Ok((size, src_addr)) => {
                            match MessageBase::from_bytes(&buf, 0) {
                                Ok(message) => {
                                    println!("{:?}", message.to_bytes());


                                    let response = Self::on_response(message);

                                    server.send_to(&response.to_bytes(), src_addr);
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

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn on_response(request: MessageBase) -> MessageBase {
        let mut response = MessageBase::new(request.get_id());
        response.set_op_code(request.get_op_code());
        response.set_qr(true);
        println!("{}", request.is_qr());
        //response.set_destination(request.get_origin().unwrap());
        //response.set_authoritative(true);

        for query in request.get_queries() {
            let record = match query.get_type() {
                Types::A => {
                    let record = ARecord::new(DnsClasses::In, false, 300, Ipv4Addr::new(127, 0, 0, 1));

                    record
                }
                /*Types::Aaaa => {}
                Types::Ns => {}
                Types::Cname => {}
                Types::Soa => {}
                Types::Ptr => {}
                Types::Mx => {}
                Types::Txt => {}
                Types::Srv => {}
                Types::Opt => {}
                Types::Rrsig => {}
                Types::Nsec => {}
                Types::DnsKey => {}
                Types::Https => {}
                Types::Spf => {}
                Types::Tsig => {}
                Types::Any => {}
                Types::Caa => {}*/
                _ => todo!()
            };

            response.add_answers(query.get_query().unwrap(), Box::new(record));
            println!("{}", query.to_string());
        }



        response
    }
}
