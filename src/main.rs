use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use crate::dns::Dns;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::messages::message_base::MessageBase;
use crate::records::a_record::ARecord;
use crate::records::inter::record_base::RecordBase;
use crate::utils::dns_query::DnsQuery;
use crate::utils::random;

mod messages;
mod records;
mod utils;
mod dns;
//GET AWAY FROM USING ENUM FOR TYPE, GO WITH METHOD USED IN rlibdht TO HANDLE CUSTOM MESSAGES

//MESSAGE ENCODE / DECODE FLAGS ARE NOT RIGHT... AD IS MISSING...

//CACHE FLUSH - LAST BYTE IS A 1.. FOR DNS_CLASS

fn main() {
    let mut dns = Dns::new();
    dns.start(6767).unwrap();

    loop {}

    /*

    let mut message = MessageBase::new(random::gen());
    //message.add_query(DnsQuery::new("outlook.office.com", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("google.com", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("gmail.com", Types::Mx, DnsClasses::In));
    message.add_query(DnsQuery::new("1.1.1.1.in-addr.arpa", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("microsoft.com", Types::Srv, DnsClasses::In));
    message.set_recursion_desired(true);

    let encoded = message.encode();
    println!("{:x?}", &encoded);

    socket.send_to(message.encode().as_slice(), SocketAddr::from((IpAddr::from([1, 1, 1, 1]), 53))).expect("Failed to send message");

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((size, src_addr)) => {
            println!("{:x?}", &buf[0..size]);

            let message = MessageBase::from_bytes(&buf, 0);
            println!("{:x?}", &message.encode());
        }
        _ => {}
    }
    */
}
