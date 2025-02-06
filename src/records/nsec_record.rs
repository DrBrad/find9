use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct NsecRecord {
    dns_class: Option<DnsClasses>,
    cache_flush: bool,
    ttl: u32,
    domain: Option<String>,
    rr_types: Vec<u16>
}

impl Default for NsecRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            cache_flush: false,
            ttl: 0,
            domain: None,
            rr_types: Vec::new()
        }
    }
}

impl DnsRecord for NsecRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf[0] = (self.get_type().get_code() >> 8) as u8;
        buf[1] = self.get_type().get_code() as u8;

        let mut dns_class = self.dns_class.unwrap().get_code();
        if self.cache_flush {
            dns_class = dns_class | 0x8000;
        }
        buf[2] = (dns_class >> 8) as u8;
        buf[3] = dns_class as u8;

        buf[4] = (self.ttl >> 24) as u8;
        buf[5] = (self.ttl >> 16) as u8;
        buf[6] = (self.ttl >> 8) as u8;
        buf[7] = self.ttl as u8;

        buf.extend_from_slice(&pack_domain(self.domain.as_ref().unwrap().as_str(), label_map, off+12));

        let bitmap_length = self.rr_types.len()*2;
        buf.extend_from_slice(&[(bitmap_length*2 >> 8) as u8, bitmap_length as u8]);

        for rr_type in self.rr_types.clone() {
            buf.extend_from_slice(&[(rr_type >> 8) as u8, rr_type as u8]);
        }

        buf[8] = (buf.len()-10 >> 8) as u8;
        buf[9] = (buf.len()-10) as u8;

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let dns_class = ((buf[off] as u16) << 8) | (buf[off+1] as u16);
        let cache_flush = (dns_class & 0x8000) != 0;
        let dns_class = Some(DnsClasses::get_class_from_code(dns_class & 0x7FFF).unwrap());

        let ttl = ((buf[off+2] as u32) << 24) |
            ((buf[off+3] as u32) << 16) |
            ((buf[off+4] as u32) << 8) |
            (buf[off+5] as u32);

        let z = ((buf[off+6] as u16) << 8) | (buf[off+7] as u16);

        let (domain, length) = unpack_domain(buf, off+8);
        off += length+8;

        let bitmap_length = off+2+(((buf[off] as u16) << 8) | (buf[off+1] as u16)) as usize;
        off += 2;

        let mut rr_types = Vec::new();

        while off < bitmap_length {
            let rr_type = ((buf[off] as u16) << 8) | buf[off+1] as u16;
            rr_types.push(rr_type);
            off += 2;
        }

        Self {
            dns_class,
            cache_flush,
            ttl,
            domain: Some(domain),
            rr_types
        }
    }

    fn get_type(&self) -> Types {
        Types::Nsec
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

impl NsecRecord {

    pub fn new(dns_classes: DnsClasses, cache_flush: bool, ttl: u32, domain: &str, rr_types: Vec<u16>) -> Self {
        Self {
            dns_class: Some(dns_classes),
            cache_flush,
            ttl,
            domain: Some(domain.to_string()),
            rr_types
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
