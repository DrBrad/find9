use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::records::inter::dns_record::DnsRecord;

#[derive(Clone)]
pub struct TxtRecord {
    dns_class: Option<DnsClasses>,
    ttl: u32,
    record: Option<String>
}

impl Default for TxtRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            record: None
        }
    }
}

impl DnsRecord for TxtRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf[0] = (self.get_type() >> 8) as u8;
        buf[1] = self.get_type() as u8;

        buf[2] = (self.dns_class.unwrap().get_code() >> 8) as u8;
        buf[3] = self.dns_class.unwrap().get_code() as u8;

        buf[4] = (self.ttl >> 24) as u8;
        buf[5] = (self.ttl >> 16) as u8;
        buf[6] = (self.ttl >> 8) as u8;
        buf[7] = self.ttl as u8;

        let encoded = self.record.as_ref().unwrap().as_bytes();

        buf[8] = (encoded.len() >> 8) as u8;
        buf[9] = encoded.len() as u8;

        buf.extend_from_slice(encoded);

        Ok(buf)
    }

    fn decode(&mut self, buf: &[u8], off: usize) {
        self.dns_class = Some(DnsClasses::get_class_from_code(((buf[off] as u16) << 8) | (buf[off+1] as u16)).unwrap());

        self.ttl = ((buf[off+2] as u32) << 24) |
            ((buf[off+3] as u32) << 16) |
            ((buf[off+4] as u32) << 8) |
            (buf[off+5] as u32);

        let length = ((buf[off+6] as u16) << 8) | (buf[off+7] as u16);
        self.record = Some(String::from_utf8(buf[8..8 + length as usize].to_vec()).unwrap());
    }

    fn get_type(&self) -> u16 {
        16
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
        format!("[RECORD] type {:?}, class {:?}, record {}", self.get_type(), self.dns_class.unwrap(), self.record.as_ref().unwrap())
    }
}

impl TxtRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, content: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            record: Some(content.to_string())
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

    pub fn set_record(&mut self, record: &str) {
        self.record = Some(record.to_string());
    }

    pub fn get_record(&self) -> Option<String> {
        self.record.clone()
    }
}
