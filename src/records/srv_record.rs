use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct SrvRecord {
    dns_class: Option<DnsClasses>,
    cache_flush: bool,
    ttl: u32,
    priority: u16,
    weight: u16,
    port: u16,
    target: Option<String>
}

impl Default for SrvRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            cache_flush: false,
            ttl: 0,
            priority: 0,
            weight: 0,
            port: 0,
            target: None
        }
    }
}

impl RecordBase for SrvRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let dns_class = u16::from_be_bytes([buf[off], buf[off+1]]);
        let cache_flush = (dns_class & 0x8000) != 0;
        let dns_class = Some(DnsClasses::from_code(dns_class & 0x7FFF).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let priority = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        let weight = u16::from_be_bytes([buf[off+10], buf[off+11]]);
        let port = u16::from_be_bytes([buf[off+12], buf[off+13]]);

        let (target, _) = unpack_domain(buf, off+14);

        Self {
            dns_class,
            cache_flush,
            ttl,
            priority,
            weight,
            port,
            target: Some(target)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 16];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());

        let mut dns_class = self.dns_class.unwrap().get_code();
        if self.cache_flush {
            dns_class = dns_class | 0x8000;
        }

        buf.splice(2..4, dns_class.to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.splice(10..12, self.priority.to_be_bytes());
        buf.splice(12..14, self.weight.to_be_bytes());
        buf.splice(14..16, self.port.to_be_bytes());

        buf.extend_from_slice(&pack_domain(self.target.as_ref().unwrap().as_str(), label_map, off+16));

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> Types {
        Types::Srv
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn upcast(&self) -> &dyn RecordBase {
        self
    }

    fn upcast_mut(&mut self) -> &mut dyn RecordBase {
        self
    }

    fn dyn_clone(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }

    fn to_string(&self) -> String {
        format!("[RECORD] type {:?}, class {:?}, target {}", self.get_type(), self.dns_class.unwrap(), self.target.as_ref().unwrap())
    }
}

impl SrvRecord {

    pub fn new(dns_classes: DnsClasses, cache_flush: bool, ttl: u32, priority: u16, weight: u16, port: u16, target: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
            cache_flush,
            ttl,
            priority,
            weight,
            port,
            target: Some(target.to_string())
        }
    }

    pub fn set_dns_class(&mut self, dns_class: DnsClasses) {
        self.dns_class = Some(dns_class);
    }

    pub fn get_dns_class(&self) -> Result<DnsClasses, String> {
        match self.dns_class {
            Some(ref dns_class) => Ok(dns_class.clone()),
            None => Err("No dns class returned".to_string())
        }
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }
}
