use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct DNSKeyRecord {
    dns_class: Option<DnsClasses>,
    cache_flush: bool,
    ttl: u32,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: Vec<u8>
}

impl Default for DNSKeyRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            cache_flush: false,
            ttl: 0,
            flags: 0,
            protocol: 0,
            algorithm: 0,
            public_key: Vec::new()
        }
    }
}

impl DnsRecord for DNSKeyRecord {

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

        //TRY NOT TO EXTEND...
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.push(self.protocol);
        buf.push(self.algorithm);

        buf.extend_from_slice(&self.public_key);

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

        let flags = ((buf[off+8] as u16) << 8) | (buf[off+9] as u16);
        /*
        Flags: 0x0100
            .... ...1 .... .... = Zone Key: This is the zone key for specified zone
            .... .... 0... .... = Key Revoked: No
            .... .... .... ...0 = Key Signing Key: No
            0000 000. .000 000. = Key Signing Key: 0x0000
        */

        let protocol = buf[off+10];
        let algorithm = buf[off+11];

        let data_length = off+8+(((buf[off+6] as u16) << 8) | (buf[off+7] as u16)) as usize;
        off += 12;

        let public_key = buf[off..data_length].to_vec();

        Self {
            dns_class,
            cache_flush,
            ttl,
            flags,
            protocol,
            algorithm,
            public_key
        }
    }

    fn get_type(&self) -> Types {
        Types::DnsKey
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

impl DNSKeyRecord {

    pub fn new(dns_classes: DnsClasses, cache_flush: bool, ttl: u32, flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8>) -> Self {
        Self {
            dns_class: Some(dns_classes),
            cache_flush,
            ttl,
            flags,
            protocol,
            algorithm,
            public_key
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
