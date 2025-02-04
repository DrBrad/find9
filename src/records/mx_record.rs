use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::records::inter::dns_record::DnsRecord;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct MxRecord {
    dns_class: Option<DnsClasses>,
    ttl: u32,
    priority: u16,
    domain: Option<String>
}

impl Default for MxRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            priority: 0,
            domain: None
        }
    }
}

impl DnsRecord for MxRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 12];

        buf[0] = (self.get_type() >> 8) as u8;
        buf[1] = self.get_type() as u8;

        buf[2] = (self.dns_class.unwrap().get_code() >> 8) as u8;
        buf[3] = self.dns_class.unwrap().get_code() as u8;

        buf[4] = (self.ttl >> 24) as u8;
        buf[5] = (self.ttl >> 16) as u8;
        buf[6] = (self.ttl >> 8) as u8;
        buf[7] = self.ttl as u8;

        buf[10] = (self.priority >> 8) as u8;
        buf[11] = self.priority as u8;

        let domain = pack_domain(self.domain.as_ref().unwrap().as_str(), label_map, off+14);

        buf[8] = (domain.len()+2 >> 8) as u8;
        buf[9] = (domain.len()+2) as u8;

        buf.extend_from_slice(&domain);

        Ok(buf)
    }

    fn decode(&mut self, buf: &[u8], off: usize) {
        self.dns_class = Some(DnsClasses::get_class_from_code(((buf[off] as u16) << 8) | (buf[off+1] as u16)).unwrap());

        self.ttl = ((buf[off+2] as u32) << 24) |
            ((buf[off+3] as u32) << 16) |
            ((buf[off+4] as u32) << 8) |
            (buf[off+5] as u32);

        let z = ((buf[off+6] as u16) << 8) | (buf[off+7] as u16);

        self.priority = ((buf[off+8] as u16) << 8) | (buf[off+9] as u16);

        let (domain, length) = unpack_domain(buf, off+10);
        self.domain = Some(domain);
    }

    fn get_type(&self) -> u16 {
        15
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
        format!("[RECORD] type {:?}, class {:?}, priority {}, domain {}", self.get_type(), self.dns_class.unwrap(), self.priority, self.domain.as_ref().unwrap())
    }
}

impl MxRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, priority: u16, domain: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            priority,
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
