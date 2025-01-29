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

    let mut message = MessageBase::new(20);
    message.add_query(DnsQuery::new("distributed.net", Types::A, DnsClasses::In));

    println!("{:?}", message.encode());


    /*
    let query = DnsQuery::new("distributed.net", Types::A, DnsClasses::In);
    let encoded = query.encode();
    println!("{:?}", encoded);

    let mut query = DnsQuery::decode(encoded.as_slice(), 0);
    println!("{} {:?} {:?}", query.get_query().unwrap(), query.get_type().get_code(), query.get_dns_class().get_code());
    */
}
