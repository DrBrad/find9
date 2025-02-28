use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::RecordBase;

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

impl RecordBase for TxtRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let dns_class = u16::from_be_bytes([buf[off], buf[off+1]]);
        let cache_flush = (dns_class & 0x8000) != 0;
        let dns_class = Some(DnsClasses::from_code(dns_class & 0x7FFF).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
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

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());

        let mut dns_class = self.dns_class.unwrap().get_code();
        if self.cache_flush {
            dns_class = dns_class | 0x8000;
        }

        buf.splice(2..4, dns_class.to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        for record in &self.records {
            buf.push(record.len() as u8);
            buf.extend_from_slice(record.as_bytes());
        }

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
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
