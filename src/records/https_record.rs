use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;
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

impl DnsRecord for HttpsRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 12];

        buf[0] = (self.get_type().get_code() >> 8) as u8;
        buf[1] = self.get_type().get_code() as u8;

        buf[2] = (self.dns_class.unwrap().get_code() >> 8) as u8;
        buf[3] = self.dns_class.unwrap().get_code() as u8;

        buf[4] = (self.ttl >> 24) as u8;
        buf[5] = (self.ttl >> 16) as u8;
        buf[6] = (self.ttl >> 8) as u8;
        buf[7] = self.ttl as u8;

        buf[10] = (self.svc_priority >> 8) as u8;
        buf[11] = self.svc_priority as u8;

        let target = pack_domain(self.target.as_ref().unwrap().as_str(), label_map, off+12);
        buf.extend_from_slice(&target);

        for (key, value) in self.params.iter() {
            buf.extend_from_slice(&key.to_be_bytes());
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(&value);
        }

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

        let svc_priority = ((buf[off+8] as u16) << 8) | (buf[off+9] as u16);

        let (target, length) = unpack_domain(&buf, off+10);

        let data_length = off+8+(((buf[off+6] as u16) << 8) | (buf[off+7] as u16)) as usize;
        off += length+10;

        let mut params = OrderedMap::new();
        while off < data_length {
            let key = ((buf[off] as u16) << 8) | (buf[off+1] as u16);
            let length = (((buf[off+2] as u16) << 8) | (buf[off+3] as u16)) as usize;
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

    fn get_type(&self) -> Types {
        Types::Https
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
