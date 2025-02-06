use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct SrvRecord {
    dns_class: Option<DnsClasses>,
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
            ttl: 0,
            priority: 0,
            weight: 0,
            port: 0,
            target: None
        }
    }
}

impl DnsRecord for SrvRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 16];

        buf[0] = (self.get_type().get_code() >> 8) as u8;
        buf[1] = self.get_type().get_code() as u8;

        buf[2] = (self.dns_class.unwrap().get_code() >> 8) as u8;
        buf[3] = self.dns_class.unwrap().get_code() as u8;

        buf[4] = (self.ttl >> 24) as u8;
        buf[5] = (self.ttl >> 16) as u8;
        buf[6] = (self.ttl >> 8) as u8;
        buf[7] = self.ttl as u8;

        buf[10] = (self.priority >> 8) as u8;
        buf[11] = self.priority as u8;

        buf[12] = (self.weight >> 8) as u8;
        buf[13] = self.weight as u8;

        buf[14] = (self.port >> 8) as u8;
        buf[15] = self.port as u8;

        buf.extend_from_slice(&pack_domain(self.target.as_ref().unwrap().as_str(), label_map, off+16));

        buf[8] = (buf.len()-10 >> 8) as u8;
        buf[9] = (buf.len()-10) as u8;

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let dns_class = Some(DnsClasses::get_class_from_code(((buf[off] as u16) << 8) | (buf[off+1] as u16)).unwrap());

        let ttl = ((buf[off+2] as u32) << 24) |
            ((buf[off+3] as u32) << 16) |
            ((buf[off+4] as u32) << 8) |
            (buf[off+5] as u32);

        let length = ((buf[off+6] as u16) << 8) | (buf[off+7] as u16);

        let priority = ((buf[off+8] as u16) << 8) | (buf[off+9] as u16);
        let weight = ((buf[off+10] as u16) << 8) | (buf[off+11] as u16);
        let port = ((buf[off+12] as u16) << 8) | (buf[off+13] as u16);

        let (target, _) = unpack_domain(buf, off+14);

        Self {
            dns_class,
            ttl,
            priority,
            weight,
            port,
            target: Some(target)
        }
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
        format!("[RECORD] type {:?}, class {:?}, target {}", self.get_type(), self.dns_class.unwrap(), self.target.as_ref().unwrap())
    }
}

impl SrvRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, priority: u16, weight: u16, port: u16, target: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
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
