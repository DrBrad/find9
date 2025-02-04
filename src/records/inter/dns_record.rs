use std::any::Any;
use std::collections::HashMap;

pub trait DnsRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String>;

    fn decode(&mut self, buf: &[u8], off: usize);

    fn get_type(&self) -> u16;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn upcast(&self) -> &dyn DnsRecord;

    fn upcast_mut(&mut self) -> &mut dyn DnsRecord;

    fn dyn_clone(&self) -> Box<dyn DnsRecord>;

    fn to_string(&self) -> String;
}
