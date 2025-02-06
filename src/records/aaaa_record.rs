use std::any::Any;
use std::collections::HashMap;
use std::net::IpAddr;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;

#[derive(Clone)]
pub struct AAAARecord {
    dns_class: Option<DnsClasses>,
    cache_flush: bool,
    ttl: u32,
    address: Option<IpAddr>
}

impl Default for AAAARecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            cache_flush: false,
            ttl: 0,
            address: None
        }
    }
}

impl DnsRecord for AAAARecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf[0] = (self.get_type().get_code() >> 8) as u8;
        buf[1] = self.get_type().get_code() as u8;

        let mut dns_class = self.dns_class.unwrap().get_code();
        if self.cache_flush {
            dns_class = dns_class | 0x7FFF;
        }
        buf[2] = (dns_class >> 8) as u8;
        buf[3] = dns_class as u8;

        buf[4] = (self.ttl >> 24) as u8;
        buf[5] = (self.ttl >> 16) as u8;
        buf[6] = (self.ttl >> 8) as u8;
        buf[7] = self.ttl as u8;

        let address = match self.address.unwrap() {
            IpAddr::V4(address) => {
                address.octets().to_vec()
            }
            IpAddr::V6(address) => {
                address.octets().to_vec()
            }
        };

        buf.extend_from_slice(&address);

        buf[8] = (buf.len()-10 >> 8) as u8;
        buf[9] = (buf.len()-10) as u8;

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let dns_class = ((buf[off] as u16) << 8) | (buf[off+1] as u16);
        let cache_flush = (dns_class & 0x8000) != 0;
        let dns_class = Some(DnsClasses::get_class_from_code(dns_class & 0x7FFF).unwrap());

        let ttl = ((buf[off+2] as u32) << 24) |
            ((buf[off+3] as u32) << 16) |
            ((buf[off+4] as u32) << 8) |
            (buf[off+5] as u32);

        let length = ((buf[off+6] as usize) << 8) | (buf[off+7] as usize);
        let record = &buf[off + 8..off + 8 + length];

        let address = match record.len() {
            4 => IpAddr::from(<[u8; 4]>::try_from(record).expect("Invalid IPv4 address")),
            16 => IpAddr::from(<[u8; 16]>::try_from(record).expect("Invalid IPv6 address")),
            _ => panic!("Invalid Inet Address")
        };

        Self {
            dns_class,
            cache_flush,
            ttl,
            address: Some(address)
        }
    }

    fn get_type(&self) -> Types {
        Types::Aaaa
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
        format!("[RECORD] type {:?}, class {:?}, addr: {}", self.get_type(), self.dns_class.unwrap(), self.address.unwrap().to_string())
    }
}

impl AAAARecord {

    pub fn new(dns_classes: DnsClasses, cache_flush: bool, ttl: u32, address: IpAddr) -> Self {
        Self {
            dns_class: Some(dns_classes),
            cache_flush,
            ttl,
            address: Some(address)
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

    pub fn set_address(&mut self, address: IpAddr) {
        self.address = Some(address);
    }

    pub fn get_address(&self) -> Option<IpAddr> {
        self.address
    }
}
