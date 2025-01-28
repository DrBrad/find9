use std::net::IpAddr;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::messages::message_base::MessageBase;
use crate::records::a_record::ARecord;
use crate::records::inter::dns_record::DnsRecord;
use crate::utils::dns_query::DnsQuery;

mod messages;
mod records;
mod utils;

fn main() {
    println!("Hello, world!");

    let mut record = ARecord::new();
    record.set_dns_class(DnsClasses::In);
    record.set_address(IpAddr::from([127, 0, 0, 1]));

    println!("{:?}", record.encode());


    let mut message = MessageBase::new(20);
    message.add_query(DnsQuery::new("distributed.net", Types::A, DnsClasses::In));

    println!("{:?}", message.encode());

}
