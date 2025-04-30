use std::{io, thread};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::messages::inter::types::Types;
use crate::messages::message_base::MessageBase;
use crate::rpc::call::Call;
use crate::rpc::response_tracker::ResponseTracker;
use crate::utils::spam_throttle::SpamThrottle;

pub struct Dns {
    server: Option<UdpSocket>,
    fallback: Vec<SocketAddr>,
    running: Arc<AtomicBool>
}

impl Dns {

    pub fn new() -> Self {
        Self {
            server: None,
            fallback: Vec::new(),
            running: Arc::new(AtomicBool::new(false))
        }
    }

    pub fn start(&mut self, port: u16) -> io::Result<JoinHandle<()>> {
        if self.is_running() {
            return Err(io::Error::new(io::ErrorKind::Other, "Server is already running"));
        }

        self.running.store(true, Ordering::Relaxed);
        self.server = Some(UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?);
        self.server.as_ref().unwrap().set_nonblocking(true)?;

        Ok(thread::spawn({
            let server = self.server.as_ref().unwrap().try_clone()?;
            let fallback = self.fallback.clone();
            let running = Arc::clone(&self.running);
            move || {
                let mut tracker = ResponseTracker::new();
                let receiver_throttle = SpamThrottle::new();

                let mut buf = [0u8; 65535];
                let mut last_decay_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis();

                while running.load(Ordering::Relaxed) {
                    match server.recv_from(&mut buf) {
                        Ok((size, src_addr)) => {
                            println!("{:x?}", &buf[..size]);

                            match MessageBase::from_bytes(&buf, 0) {
                                Ok(mut message) => {
                                    message.set_origin(src_addr);
                                    message.set_destination(server.local_addr().unwrap());

                                    if message.is_qr() {
                                        if let Some(call) = tracker.poll(message.get_id()) {
                                            message.set_authoritative(false);
                                            server.send_to(&message.to_bytes(), call.get_address()).unwrap();
                                        }

                                        continue;
                                    }

                                    match Self::on_response(&message) {
                                        Ok(mut response) => {
                                            response.set_authoritative(true);
                                            server.send_to(&response.to_bytes(), response.get_destination().unwrap()).unwrap();
                                        }
                                        Err(_) => {
                                            tracker.add(message.get_id(), Call::new(message.get_origin().unwrap()));
                                            server.send_to(&message.to_bytes(), fallback.get(0).unwrap()).unwrap();
                                        }
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        _ => break
                    }

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_millis();

                    if now - last_decay_time >= 1000 {
                        receiver_throttle.decay();
                        tracker.remove_stalled();

                        last_decay_time = now;
                    }
                }
            }
        }))
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn add_fallback(&mut self, addr: SocketAddr) {
        self.fallback.push(addr);
    }

    pub fn remove_fallback(&mut self, addr: SocketAddr) {
        self.fallback.retain(|&x| x != addr);
    }

    fn on_response(request: &MessageBase) -> io::Result<MessageBase> {
        let mut response = MessageBase::new(request.get_id());
        response.set_op_code(request.get_op_code());
        response.set_qr(true);
        response.set_origin(request.get_destination().unwrap());
        response.set_destination(request.get_origin().unwrap());

        for query in request.get_queries() {
            match query.get_type() {
                Types::A => {
                    //response.add_query(query.clone());

                    //let record = ARecord::new(query.get_dns_class(), false, 300, Ipv4Addr::new(8, 8, 8, 8));
                    //response.add_answers(query.get_query().unwrap(), Box::new(record));

                    return Err(io::Error::new(io::ErrorKind::Other, "Document not found"));
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
            }
        }



        Ok(response)
    }
}
