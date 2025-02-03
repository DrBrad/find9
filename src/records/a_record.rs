use std::any::Any;
use std::collections::HashMap;
use std::net::IpAddr;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::dns_record::DnsRecord;

#[derive(Clone)]
pub struct ARecord {
    dns_class: Option<DnsClasses>,
    ttl: u32,
    address: Option<IpAddr>
}

impl Default for ARecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            address: None
        }
    }
}

impl DnsRecord for ARecord {

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

        let address = match self.address.unwrap() {
            IpAddr::V4(address) => {
                address.octets().to_vec()
            }
            IpAddr::V6(address) => {
                address.octets().to_vec()
            }
        };

        buf[8] = (address.len() >> 8) as u8;
        buf[9] = address.len() as u8;

        buf.extend_from_slice(&address);

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let _type = Types::get_type_from_code(((buf[off] as u16) << 8) | (buf[off+1] as u16)).unwrap();
        let dns_class = Some(DnsClasses::get_class_from_code(((buf[off+2] as u16) << 8) | (buf[off+3] as u16)).unwrap());

        let ttl = ((buf[off+4] as u32) << 24) |
                ((buf[off+5] as u32) << 16) |
                ((buf[off+6] as u32) << 8) |
                (buf[off+7] as u32);

        let length = ((buf[off+8] as usize) << 8) | (buf[off+9] as usize);
        let record = &buf[off + 10..off + 10 + length];

        let address = match record.len() {
            4 => IpAddr::from(<[u8; 4]>::try_from(record).expect("Invalid IPv4 address")),
            16 => IpAddr::from(<[u8; 16]>::try_from(record).expect("Invalid IPv6 address")),
            _ => panic!("Invalid Inet Address")
        };

        Self {
            dns_class,
            ttl,
            address: Some(address)
        }
    }

    /*
    fn get_length(&self) -> usize {
        self.length
    }
    */

    fn set_dns_class(&mut self, dns_class: DnsClasses) {
        self.dns_class = Some(dns_class);
    }

    fn get_dns_class(&self) -> Result<DnsClasses, String> {
        match self.dns_class {
            Some(ref dns_class) => Ok(dns_class.clone()),
            None => Err("No dns class returned".to_string())
        }
    }

    fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    fn get_ttl(&self) -> u32 {
        self.ttl
    }

    fn get_type(&self) -> Types {
        Types::A
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
        format!("[RECORD] type {:?}, class {:?}, addr: {}", Types::A, self.dns_class.unwrap(), self.address.unwrap().to_string())
    }
}

impl ARecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, address: IpAddr) -> Self {
        let length = match address {
            IpAddr::V4(address) => {
                address.octets().len()
            }
            IpAddr::V6(address) => {
                address.octets().len()
            }
        };

        Self {
            dns_class: Some(dns_classes),
            ttl,
            address: Some(address)
        }
    }

    pub fn set_address(&mut self, address: IpAddr) {
        let length = match self.address.unwrap() {
            IpAddr::V4(address) => {
                address.octets().len()
            }
            IpAddr::V6(address) => {
                address.octets().len()
            }
        };

        self.address = Some(address);
    }

    pub fn get_address(&self) -> Option<IpAddr> {
        self.address
    }
}
