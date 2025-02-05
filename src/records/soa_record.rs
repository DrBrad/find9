use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;
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

impl DnsRecord for SoaRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf[0] = (self.get_type().get_code() >> 8) as u8;
        buf[1] = self.get_type().get_code() as u8;

        buf[2] = (self.dns_class.unwrap().get_code() >> 8) as u8;
        buf[3] = self.dns_class.unwrap().get_code() as u8;

        buf[4] = (self.ttl >> 24) as u8;
        buf[5] = (self.ttl >> 16) as u8;
        buf[6] = (self.ttl >> 8) as u8;
        buf[7] = self.ttl as u8;

        let domain = pack_domain(self.domain.as_ref().unwrap().as_str(), label_map, off+10);

        buf.extend_from_slice(&domain);

        let mut off = 12+domain.len();

        let mailbox = pack_domain(self.mailbox.as_ref().unwrap().as_str(), label_map, off+12);
        buf.extend_from_slice(&mailbox);

        buf.extend_from_slice(&[(self.serial_number >> 24) as u8, (self.serial_number >> 16) as u8, (self.serial_number >> 8) as u8, self.serial_number as u8]);
        buf.extend_from_slice(&[(self.refresh_interval >> 24) as u8, (self.refresh_interval >> 16) as u8, (self.refresh_interval >> 8) as u8, self.refresh_interval as u8]);
        buf.extend_from_slice(&[(self.retry_interval >> 24) as u8, (self.retry_interval >> 16) as u8, (self.retry_interval >> 8) as u8, self.retry_interval as u8]);
        buf.extend_from_slice(&[(self.expire_limit >> 24) as u8, (self.expire_limit >> 16) as u8, (self.expire_limit >> 8) as u8, self.expire_limit as u8]);
        buf.extend_from_slice(&[(self.minimum_ttl >> 24) as u8, (self.minimum_ttl >> 16) as u8, (self.minimum_ttl >> 8) as u8, self.minimum_ttl as u8]);

        buf[8] = (buf.len()-10 >> 8) as u8;
        buf[9] = (buf.len()-10) as u8;

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let dns_class = Some(DnsClasses::get_class_from_code(((buf[off] as u16) << 8) | (buf[off+1] as u16)).unwrap());

        let ttl = ((buf[off+2] as u32) << 24) |
            ((buf[off+3] as u32) << 16) |
            ((buf[off+4] as u32) << 8) |
            (buf[off+5] as u32);

        let z = ((buf[off+6] as u16) << 8) | (buf[off+7] as u16);

        let (domain, length) = unpack_domain(buf, off+8);
        off += length+8;

        let (mailbox, length) = unpack_domain(buf, off);
        off += length;

        let serial_number = ((buf[off] as u32) << 24) |
            ((buf[off+1] as u32) << 16) |
            ((buf[off+2] as u32) << 8) |
            (buf[off+3] as u32);

        let refresh_interval = ((buf[off+4] as u32) << 24) |
            ((buf[off+5] as u32) << 16) |
            ((buf[off+6] as u32) << 8) |
            (buf[off+7] as u32);

        let retry_interval = ((buf[off+8] as u32) << 24) |
            ((buf[off+9] as u32) << 16) |
            ((buf[off+10] as u32) << 8) |
            (buf[off+11] as u32);

        let expire_limit = ((buf[off+12] as u32) << 24) |
            ((buf[off+13] as u32) << 16) |
            ((buf[off+14] as u32) << 8) |
            (buf[off+15] as u32);

        let minimum_ttl = ((buf[off+16] as u32) << 24) |
            ((buf[off+17] as u32) << 16) |
            ((buf[off+18] as u32) << 8) |
            (buf[off+19] as u32);

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

    fn get_type(&self) -> Types {
        Types::Soa
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
