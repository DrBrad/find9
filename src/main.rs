use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use crate::dns::Dns;

mod messages;
mod records;
mod utils;
mod dns;
mod rpc;
mod database;

//MESSAGE ENCODE / DECODE FLAGS ARE NOT RIGHT... AD IS MISSING...

//CACHE FLUSH - LAST BYTE IS A 1.. FOR DNS_CLASS

fn main() {
    let mut dns = Dns::new();
    dns.add_fallback(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
    dns.set_database("records.db");
    dns.start(6767).unwrap();

    loop {}


    /*
    let x = vec![ 0xa7, 0xa2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f,
                  0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
                  0x00, 0x01, 0x00, 0x00, 0x01, 0x23, 0x00, 0x04, 0x8e, 0xfa, 0x45, 0xee, 0x00, 0x00, 0x29, 0x04,
                  0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ];
    println!("{:x?}", &x);

    let message = MessageBase::from_bytes(&x, 0).unwrap();
    println!("{:x?}", message.to_bytes());
    */

    /*

    let mut message = MessageBase::new(random::gen());
    //message.add_query(DnsQuery::new("outlook.office.com", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("google.com", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("gmail.com", Types::Mx, DnsClasses::In));
    message.add_query(DnsQuery::new("1.1.1.1.in-addr.arpa", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("microsoft.com", Types::Srv, DnsClasses::In));
    message.set_recursion_desired(true);

    let encoded = message.to_bytes();
    println!("{:x?}", &encoded);

    //socket.send_to(message.encode().as_slice(), SocketAddr::from((IpAddr::from([1, 1, 1, 1]), 53))).expect("Failed to send message");

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((size, src_addr)) => {
            println!("{:x?}", &buf[0..size]);

            let message = MessageBase::from_bytes(&buf, 0);
            println!("{:x?}", &message.encode());
        }
        _ => {}
    }*/
}
