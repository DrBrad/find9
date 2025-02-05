use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::messages::message_base::MessageBase;
use crate::records::a_record::ARecord;
use crate::records::inter::record_base::DnsRecord;
use crate::utils::dns_query::DnsQuery;
use crate::utils::random;

mod messages;
mod records;
mod utils;

//GET AWAY FROM USING ENUM FOR TYPE, GO WITH METHOD USED IN rlibdht TO HANDLE CUSTOM MESSAGES

//MESSAGE ENCODE / DECODE FLAGS ARE NOT RIGHT... AD IS MISSING...

fn main() {
    /*
    //A AND CNAME CHECK
    let hex_data: Vec<u8> = vec![
        0xaf, 0xcc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x07, 0x6f, 0x75, 0x74,
        0x6c, 0x6f, 0x6f, 0x6b, 0x06, 0x6f, 0x66, 0x66, 0x69, 0x63, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x23, 0x00, 0x0c,
        0x09, 0x73, 0x75, 0x62, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0xc0, 0x14, 0xc0, 0x30, 0x00, 0x05,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x2a, 0x00, 0x14, 0x07, 0x6f, 0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b,
        0x09, 0x6f, 0x66, 0x66, 0x69, 0x63, 0x65, 0x33, 0x36, 0x35, 0xc0, 0x1b, 0xc0, 0x48, 0x00, 0x05,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x0e, 0x06, 0x6f, 0x6f, 0x63, 0x2d, 0x67, 0x32, 0x04,
        0x74, 0x6d, 0x2d, 0x34, 0xc0, 0x14, 0xc0, 0x68, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0f,
        0x00, 0x12, 0x07, 0x6f, 0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b, 0x07, 0x6d, 0x73, 0x2d, 0x61, 0x63,
        0x64, 0x63, 0xc0, 0x14, 0xc0, 0x82, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x33, 0x00, 0x0a,
        0x07, 0x43, 0x59, 0x53, 0x2d, 0x65, 0x66, 0x7a, 0xc0, 0x8a, 0xc0, 0xa0, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x34, 0x60, 0xe4, 0xc2, 0xc0, 0xa0, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x28, 0x63, 0xa5, 0x72, 0xc0, 0xa0, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x28, 0x63, 0xa5, 0x22, 0xc0, 0xa0, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x28, 0x63, 0xfd, 0x82, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    ];

    //OPT CHECK
    let hex_data = vec![
        0xcc, 0xe6, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0xa, 0x0, 0x8, 0x3b, 0xa9, 0x53, 0x3, 0x53, 0xb6, 0x4, 0xef, 0x0, 0xb, 0x0, 0x0
    ];

    //HTTP CHECK...
    let hex_data = vec![
        0x15, 0xa3, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x8, 0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x63, 0x65, 0x5, 0x74, 0x65, 0x61, 0x6d, 0x73, 0x9, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x41, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x3, 0x81, 0x4b, 0x0, 0x2a, 0x8, 0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x63, 0x65, 0x8, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x3, 0x73, 0x66, 0x62, 0xe, 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x50, 0x0, 0x6, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1d, 0x0, 0x2e, 0x3, 0x74, 0x6d, 0x31, 0x6, 0x64, 0x6e, 0x73, 0x2d, 0x74, 0x6d, 0xc0, 0x25, 0xa, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x50, 0x77, 0x64, 0x96, 0x60, 0x0, 0x0, 0x3, 0x84, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x24, 0xea, 0x0, 0x0, 0x0, 0x0, 0x1e, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
    ];
    */

    //MDNS
    let hex_data = vec![
        0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x24, 0x33, 0x36, 0x39, 0x45, 0x38, 0x36, 0x44, 0x34, 0x2d, 0x38, 0x42, 0x33, 0x41, 0x2d, 0x34, 0x31, 0x33, 0x39, 0x2d, 0x38, 0x31, 0x36, 0x30, 0x2d, 0x41, 0x36, 0x36, 0x42, 0x36, 0x31, 0x32, 0x46, 0x44, 0x30, 0x31, 0x42, 0xe, 0x5f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x70, 0x61, 0x69, 0x72, 0x69, 0x6e, 0x67, 0x4, 0x5f, 0x74, 0x63, 0x70, 0x5, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x0, 0x0, 0xff, 0x0, 0x1, 0x38, 0x30, 0x38, 0x3a, 0x63, 0x37, 0x3a, 0x32, 0x39, 0x3a, 0x35, 0x32, 0x3a, 0x66, 0x35, 0x3a, 0x61, 0x30, 0x40, 0x66, 0x65, 0x38, 0x30, 0x3a, 0x3a, 0x61, 0x63, 0x37, 0x3a, 0x32, 0x39, 0x66, 0x66, 0x3a, 0x66, 0x65, 0x35, 0x32, 0x3a, 0x66, 0x35, 0x61, 0x30, 0x2d, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x52, 0x50, 0x2d, 0x32, 0x32, 0xe, 0x5f, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d, 0x6d, 0x6f, 0x62, 0x64, 0x65, 0x76, 0x32, 0xc0, 0x40, 0x0, 0xff, 0x0, 0x1, 0xd, 0x69, 0x50, 0x68, 0x6f, 0x6e, 0x65, 0x2d, 0x31, 0x32, 0x2d, 0x50, 0x72, 0x6f, 0xc0, 0x45, 0x0, 0xff, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x21, 0x0, 0x1, 0x0, 0x0, 0x11, 0x94, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0xc0, 0x0, 0xc0, 0x9e, 0xc0, 0x50, 0x0, 0x21, 0x0, 0x1, 0x0, 0x0, 0x11, 0x94, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x7e, 0xf2, 0xc0, 0x9e, 0xc0, 0x9e, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x11, 0x94, 0x0, 0x10, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x18, 0x2c, 0x35, 0x6c, 0xd6, 0x4c, 0x5e, 0xea, 0xc0, 0x9e, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x11, 0x94, 0x0, 0x4, 0xa, 0x1, 0xc, 0x8d
    ];

    let mut message = MessageBase::decode(&hex_data, 0);
    println!("{:x?}", hex_data);
    println!("");
    println!("{:x?}", message.encode());

    return;


    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).expect("Failed to bind socket");

    let mut message = MessageBase::new(random::gen());
    //message.add_query(DnsQuery::new("outlook.office.com", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("google.com", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("gmail.com", Types::Mx, DnsClasses::In));
    //message.add_query(DnsQuery::new("1.1.1.1.in-addr.arpa", Types::A, DnsClasses::In));
    message.add_query(DnsQuery::new("microsoft.com", Types::Srv, DnsClasses::In));
    message.set_recursion_desired(true);

    //message.add_query(DnsQuery::new("github.com", Types::Aaaa, DnsClasses::In));


    let encoded = message.encode();
    println!("{:?}", &encoded);

    socket.send_to(message.encode().as_slice(), SocketAddr::from((IpAddr::from([1, 1, 1, 1]), 53))).expect("Failed to send message");

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((size, src_addr)) => {
            println!("{:?}", &buf[0..size]);

            let message = MessageBase::decode(&buf, 0);
            println!("{:?}", &message.encode());
        }
        _ => {}
    }
}
