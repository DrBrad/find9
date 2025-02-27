use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;

pub trait RecordBase {

    fn from_bytes(buf: &[u8], off: usize) -> Self where Self: Sized;

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String>;

    fn get_type(&self) -> Types;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn upcast(&self) -> &dyn RecordBase;

    fn upcast_mut(&mut self) -> &mut dyn RecordBase;

    fn dyn_clone(&self) -> Box<dyn RecordBase>;

    fn to_string(&self) -> String;
}
