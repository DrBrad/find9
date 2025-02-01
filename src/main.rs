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

//should message decode return self type

//

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

    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).expect("Failed to bind socket");

    let mut message = MessageBase::new(20);
    message.add_query(DnsQuery::new("google.com", Types::A, DnsClasses::In));

    socket.send_to(message.encode().as_slice(), SocketAddr::from((IpAddr::from([1, 1, 1, 1]), 53))).expect("Failed to send message");

    let mut buf = [0u8; 65535];
    match socket.recv_from(&mut buf) {
        Ok((size, src_addr)) => {
            let message = MessageBase::decode(&buf, 0);
            println!("{:?}", message.encode());

            for query in message.get_queries() {
                println!("QR: {} {}", query.get_query().unwrap(), query.get_type().get_code());
            }

            for (key, record) in message.get_answers() {
                let arecord = record.as_any().downcast_ref::<ARecord>().unwrap();
                println!("AN: {} {} {} {:?}", key, record.get_type().get_code(), record.get_ttl(), arecord.get_address().unwrap());
            }

            for (key, record) in message.get_name_servers() {
                println!("NS: {} {} {}", key, record.get_type().get_code(), record.get_ttl());
            }

            for (key, record) in message.get_additional_records() {
                println!("AR: {} {} {}", key, record.get_type().get_code(), record.get_ttl());
            }
        }
        _ => {}
    }


    /*
    let mut message = MessageBase::new(20);
    message.add_query(DnsQuery::new("distributed.net", Types::A, DnsClasses::In));
    message.add_answers("distributed.net", ARecord::new(DnsClasses::In, 32, IpAddr::from([127, 0, 0, 1])).dyn_clone());

    let encoded = message.encode();
    println!("{:?}", encoded);

    message.decode(&encoded, 0);
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
