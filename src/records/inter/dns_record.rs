use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;

pub trait DnsRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String>;

    fn decode(buf: &[u8], off: usize) -> Self where Self: Sized;

    fn get_length(&self) -> usize;

    fn set_dns_class(&mut self, dns_class: DnsClasses);

    fn get_dns_class(&self) -> Result<DnsClasses, String>;

    fn set_ttl(&mut self, ttl: u32);

    fn get_ttl(&self) -> u32;

    fn get_type(&self) -> Types;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn upcast(&self) -> &dyn DnsRecord;

    fn upcast_mut(&mut self) -> &mut dyn DnsRecord;

    fn dyn_clone(&self) -> Box<dyn DnsRecord>;

    fn to_string(&self) -> String;
}
