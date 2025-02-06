use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;

#[derive(Clone)]
pub struct TxtRecord {
    dns_class: Option<DnsClasses>,
    cache_flush: bool,
    ttl: u32,
    records: Vec<String>
}

impl Default for TxtRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            cache_flush: false,
            ttl: 0,
            records: Vec::new()
        }
    }
}

impl DnsRecord for TxtRecord {

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

        for record in &self.records {
            buf.push(record.len() as u8);
            buf.extend_from_slice(record.as_bytes());
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

        let data_length = off+8+(((buf[off+6] as u16) << 8) | (buf[off+7] as u16)) as usize;
        off += 8;

        let mut records = Vec::new();

        while off < data_length {
            let length = buf[off] as usize;
            let record = String::from_utf8(buf[off + 1..off + 1 + length].to_vec()).unwrap();
            records.push(record);
            off += length+1;
        }

        Self {
            dns_class,
            cache_flush,
            ttl,
            records
        }
    }

    fn get_type(&self) -> Types {
        Types::Txt
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
        format!("[RECORD] type {:?}, class {:?}", self.get_type(), self.dns_class.unwrap())
    }
}

impl TxtRecord {

    pub fn new(dns_classes: DnsClasses, cache_flush: bool, ttl: u32, records: Vec<String>) -> Self {
        Self {
            dns_class: Some(dns_classes),
            cache_flush,
            ttl,
            records
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
