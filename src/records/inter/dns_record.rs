use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;

pub trait DnsRecord {

    fn encode(&self) -> Result<Vec<u8>, String>;

    fn decode(buf: &[u8], off: usize) -> Self where Self: Sized;

    fn length(&self) -> usize;

    fn set_type(&mut self, _type: Types);

    fn get_type(&self) -> Types;

    fn set_dns_class(&mut self, dns_class: DnsClasses);

    fn get_dns_class(&self) -> Result<DnsClasses, String>;

    fn set_ttl(&mut self, ttl: u32);

    fn get_ttl(&self) -> u32;

    fn set_query(&mut self, query: String);

    fn get_query(&self) -> Option<String>;

    fn get_length(&self) -> usize;
}
