use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct SoaRecord {
    dns_class: Option<DnsClasses>,
    ttl: u32,
    domain: Option<String>,
    mailbox: Option<String>,
    serial_number: u32,
    refresh_interval: u32,
    retry_interval: u32,
    expire_limit: u32,
    minimum_ttl: u32
}

impl Default for SoaRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            domain: None,
            mailbox: None,
            serial_number: 0,
            refresh_interval: 0,
            retry_interval: 0,
            expire_limit: 0,
            minimum_ttl: 0
        }
    }
}

impl RecordBase for SoaRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let dns_class = Some(DnsClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (domain, length) = unpack_domain(buf, off+8);
        off += length+8;

        let (mailbox, length) = unpack_domain(buf, off);
        off += length;

        let serial_number = u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        let refresh_interval = u32::from_be_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);
        let retry_interval = u32::from_be_bytes([buf[off+8], buf[off+9], buf[off+10], buf[off+11]]);
        let expire_limit = u32::from_be_bytes([buf[off+12], buf[off+13], buf[off+14], buf[off+15]]);
        let minimum_ttl = u32::from_be_bytes([buf[off+16], buf[off+17], buf[off+18], buf[off+19]]);

        Self {
            dns_class,
            ttl,
            domain: Some(domain),
            mailbox: Some(mailbox),
            serial_number,
            refresh_interval,
            retry_interval,
            expire_limit,
            minimum_ttl
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut off = off;

        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.dns_class.unwrap().get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        let domain = pack_domain(self.domain.as_ref().unwrap().as_str(), label_map, off+12);
        buf.extend_from_slice(&domain);

        off += 12+domain.len();

        let mailbox = pack_domain(self.mailbox.as_ref().unwrap().as_str(), label_map, off+12);
        buf.extend_from_slice(&mailbox);

        buf.extend_from_slice(&self.serial_number.to_be_bytes());
        buf.extend_from_slice(&self.refresh_interval.to_be_bytes());
        buf.extend_from_slice(&self.retry_interval.to_be_bytes());
        buf.extend_from_slice(&self.expire_limit.to_be_bytes());
        buf.extend_from_slice(&self.minimum_ttl.to_be_bytes());

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> Types {
        Types::Soa
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
        format!("[RECORD] type {:?}, class {:?}, domain {}", self.get_type(), self.dns_class.unwrap(), self.domain.as_ref().unwrap())
    }
}

impl SoaRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, domain: &str, mailbox: &str, serial_number: u32, refresh_interval: u32, retry_interval: u32, expire_limit: u32, minimum_ttl: u32) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            domain: Some(domain.to_string()),
            mailbox: Some(mailbox.to_string()),
            serial_number,
            refresh_interval,
            retry_interval,
            expire_limit,
            minimum_ttl
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
