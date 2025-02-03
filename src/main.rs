use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::messages::message_base::MessageBase;
use crate::records::a_record::ARecord;
use crate::records::inter::dns_record::DnsRecord;
use crate::utils::dns_query::DnsQuery;

mod messages;
mod records;
mod utils;

//SHOULD THE RECORDS BE IN A HASH-MAP OR VECTOR....

//We may want to handle query to answers differently as we may want to query with a and aaaa types...

fn main() {
    /*
    let mut record = ARecord::new();
    record.set_dns_class(DnsClasses::In);
    record.set_address(IpAddr::from([127, 0, 0, 1]));
    record.set_ttl(32);

    let encoded = record.encode().unwrap();

    println!("{:?}", encoded);

    let record = ARecord::decode(&encoded, 0);
    println!("{:?}", record.encode().unwrap());
    */




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


    let mut message = MessageBase::decode(&hex_data, 0);
    println!("{:x?}", hex_data);
    println!("");
    println!("{:x?}", message.encode());


    /*
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).expect("Failed to bind socket");

    let mut message = MessageBase::new(20);
    message.add_query(DnsQuery::new("outlook.office.com", Types::A, DnsClasses::In));
    message.set_recursion_desired(true);

    //message.add_query(DnsQuery::new("github.com", Types::Aaaa, DnsClasses::In));


    let encoded = message.encode();
    println!("{:?}", encoded);

    socket.send_to(message.encode().as_slice(), SocketAddr::from((IpAddr::from([1, 1, 1, 1]), 53))).expect("Failed to send message");

    let mut buf = [0u8; 65535];
    match socket.recv_from(&mut buf) {
        Ok((size, src_addr)) => {
            println!("{:?}", buf);

            let message = MessageBase::decode(&buf, 0);
            println!("{:?}", message.encode());

            /.*
            for query in message.get_queries() {
                println!("QR: {} {}", query.get_query().unwrap(), query.get_type().get_code());
            }

            for (key, record) in message.get_answers() {
                //let arecord = record.as_any().downcast_ref::<ARecord>().unwrap();
                println!("AN: {} {} {}", key, record.get_type().get_code(), record.get_ttl());
            }

            for (key, record) in message.get_name_servers() {
                println!("NS: {} {} {}", key, record.get_type().get_code(), record.get_ttl());
            }

            for (key, record) in message.get_additional_records() {
                println!("AR: {} {} {}", key, record.get_type().get_code(), record.get_ttl());
            }
            *./
        }
        _ => {}
    }
    */



    /*
    let mut message = MessageBase::new(20);
    message.add_query(DnsQuery::new("distributed.net", Types::A, DnsClasses::In));
    message.add_answers("distributed.net", ARecord::new(DnsClasses::In, 32, IpAddr::from([127, 0, 0, 1])).dyn_clone());

    let encoded = message.encode();
    println!("{:?}", encoded);

    let mut message = MessageBase::decode(&encoded, 0);
    println!("{:?}", message.encode());
    */

    /*
    let query = DnsQuery::new("distributed.net", Types::A, DnsClasses::In);
    let encoded = query.encode();
    println!("{:?}", encoded);

    let mut query = DnsQuery::decode(encoded.as_slice(), 0);
    println!("{} {:?} {:?}", query.get_query().unwrap(), query.get_type().get_code(), query.get_dns_class().get_code());
    */
}
