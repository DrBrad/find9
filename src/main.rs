use std::net::{IpAddr, Ipv4Addr};
use crate::messages::inter::dns_classes::DnsClasses;
use crate::records::a_record::ARecord;
use crate::records::inter::dns_record::DnsRecord;

mod messages;
mod records;

fn main() {
    println!("Hello, world!");

    let mut record = ARecord::new();
    record.set_dns_class(DnsClasses::In);
    record.set_address(IpAddr::from([127, 0, 0, 1]));

    println!("{:?}", record.encode());
}
