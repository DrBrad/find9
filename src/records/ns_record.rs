use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct NsRecord {
    dns_class: Option<DnsClasses>,
    ttl: u32,
    domain: Option<String>
}

impl Default for NsRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            domain: None
        }
    }
}

impl DnsRecord for NsRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.dns_class.unwrap().get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_domain(self.domain.as_ref().unwrap().as_str(), label_map, off+12));

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let dns_class = Some(DnsClasses::get_class_from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (domain, _) = unpack_domain(buf, off+8);

        Self {
            dns_class,
            ttl,
            domain: Some(domain)
        }
    }

    fn get_type(&self) -> Types {
        Types::Ns
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn upcast(&self) -> &dyn DnsRecord {
        self
    }

    fn upcast_mut(&mut self) -> &mut dyn DnsRecord {
        self
    }

    fn dyn_clone(&self) -> Box<dyn DnsRecord> {
        Box::new(self.clone())
    }

    fn to_string(&self) -> String {
        format!("[RECORD] type {:?}, class {:?}, domain {}", self.get_type(), self.dns_class.unwrap(), self.domain.as_ref().unwrap())
    }
}

impl NsRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, domain: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            domain: Some(domain.to_string())
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

    pub fn set_domain(&mut self, domain: &str) {
        self.domain = Some(domain.to_string());
    }

    pub fn get_domain(&self) -> Option<String> {
        self.domain.clone()
    }
}
