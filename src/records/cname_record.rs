use std::any::Any;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::dns_record::DnsRecord;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct CNameRecord {
    dns_class: Option<DnsClasses>,
    ttl: u32,
    domain: Option<String>,
    length: usize
}

impl Default for CNameRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            domain: None,
            length: 8
        }
    }
}

impl DnsRecord for CNameRecord {

    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; self.length];

        buf[0] = (self.get_type().get_code() >> 8) as u8;
        buf[1] = self.get_type().get_code() as u8;

        buf[2] = (self.dns_class.unwrap().get_code() >> 8) as u8;
        buf[3] = self.dns_class.unwrap().get_code() as u8;

        buf[4] = (self.ttl >> 24) as u8;
        buf[5] = (self.ttl >> 16) as u8;
        buf[6] = (self.ttl >> 8) as u8;
        buf[7] = self.ttl as u8;

        let domain = pack_domain(self.domain.as_ref().unwrap().as_str());
        buf[10..10 + domain.len()].copy_from_slice(&domain);

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let _type = Types::get_type_from_code(((buf[off] as u16) << 8) | (buf[off+1] as u16)).unwrap();
        let dns_class = Some(DnsClasses::get_class_from_code(((buf[off+2] as u16) << 8) | (buf[off+3] as u16)).unwrap());

        let ttl = ((buf[off+4] as u32) << 24) |
            ((buf[off+5] as u32) << 16) |
            ((buf[off+6] as u32) << 8) |
            (buf[off+7] as u32);

        let z = ((buf[off+8] as u16) << 8) | (buf[off+9] as u16);

        let (domain, length) = unpack_domain(buf, off+10);

        Self {
            dns_class,
            ttl,
            domain: Some(domain),
            length: length+10
        }
    }

    fn get_length(&self) -> usize {
        self.length
    }

    fn set_dns_class(&mut self, dns_class: DnsClasses) {
        self.dns_class = Some(dns_class);
    }

    fn get_dns_class(&self) -> Result<DnsClasses, String> {
        match self.dns_class {
            Some(ref dns_class) => Ok(dns_class.clone()),
            None => Err("No dns class returned".to_string())
        }
    }

    fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    fn get_ttl(&self) -> u32 {
        self.ttl
    }

    fn get_type(&self) -> Types {
        Types::A
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
        format!("[RECORD] type {:?}, class {:?}, cname: {}", Types::Cname, self.dns_class.unwrap(), self.domain.as_ref().unwrap())
    }
}

impl CNameRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, domain: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            domain: Some(domain.to_string()),
            length: domain.len()+10
        }
    }

    pub fn set_domain(&mut self, domain: &str) {
        self.domain = Some(domain.to_string());
        self.length = domain.len()+10;
    }

    pub fn get_domain(&self) -> Option<String> {
        self.domain.clone()
    }
}
