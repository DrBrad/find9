use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::{pack_domain, unpack_domain};
use crate::utils::ordered_map::OrderedMap;

#[derive(Clone)]
pub struct HttpsRecord {
    dns_class: Option<DnsClasses>,
    ttl: u32,
    svc_priority: u16,
    target: Option<String>,
    params: OrderedMap<u16, Vec<u8>>
}

impl Default for HttpsRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            svc_priority: 0,
            target: None,
            params: OrderedMap::new()
        }
    }
}

impl RecordBase for HttpsRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let dns_class = Some(DnsClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let svc_priority = u16::from_be_bytes([buf[off+8], buf[off+9]]);

        let (target, length) = unpack_domain(&buf, off+10);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += length+10;

        let mut params = OrderedMap::new();
        while off < data_length {
            let key = u16::from_be_bytes([buf[off], buf[off+1]]);
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            params.insert(key, buf[off + 4..off + 4 + length].to_vec());
            off += length+4;
        }

        Self {
            dns_class,
            ttl,
            svc_priority,
            target: Some(target),
            params
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 12];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.dns_class.unwrap().get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.splice(10..12, self.svc_priority.to_be_bytes());

        let target = pack_domain(self.target.as_ref().unwrap().as_str(), label_map, off+12);
        buf.extend_from_slice(&target);

        for (key, value) in self.params.iter() {
            buf.extend_from_slice(&key.to_be_bytes());
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(&value);
        }

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> Types {
        Types::Https
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

impl HttpsRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, svc_priority: u16, target: &str, params: OrderedMap<u16, Vec<u8>>) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            svc_priority,
            target: Some(target.to_string()),
            params
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
