use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;

pub trait DnsRecord {

    fn encode(&self) -> Vec<u8>;

    fn decode(buf: Vec<u8>, off: usize) -> Self;

    fn length(&self) -> usize;

    fn set_type(&mut self, _type: Types);

    fn get_type(&self) -> Types;

    fn set_dns_class(&mut self, dns_class: DnsClasses);

    fn get_dns_class(&self) -> DnsClasses;
}
