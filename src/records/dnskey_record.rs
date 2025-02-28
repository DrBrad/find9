use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::RecordBase;

#[derive(Clone)]
pub struct DNSKeyRecord {
    dns_class: Option<DnsClasses>,
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
            ttl: 0,
            flags: 0,
            protocol: 0,
            algorithm: 0,
            public_key: Vec::new()
        }
    }
}

impl RecordBase for DNSKeyRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let dns_class = Some(DnsClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let flags = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        /*
        Flags: 0x0100
            .... ...1 .... .... = Zone Key: This is the zone key for specified zone
            .... .... 0... .... = Key Revoked: No
            .... .... .... ...0 = Key Signing Key: No
            0000 000. .000 000. = Key Signing Key: 0x0000
        */

        let protocol = buf[off+10];
        let algorithm = buf[off+11];

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += 12;

        let public_key = buf[off..data_length].to_vec();

        Self {
            dns_class,
            ttl,
            flags,
            protocol,
            algorithm,
            public_key
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 14];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.dns_class.unwrap().get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.splice(10..12, self.flags.to_be_bytes());
        buf[12] = self.protocol;
        buf[13] = self.algorithm;

        buf.extend_from_slice(&self.public_key);

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
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

impl DNSKeyRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8>) -> Self {
        Self {
            dns_class: Some(dns_classes),
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
