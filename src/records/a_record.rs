use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::dns_record::DnsRecord;

#[derive(Clone)]
pub struct ARecord {
    _type: Types,
    dns_class: Option<DnsClasses>,
    ttl: u32,
    query: Option<String>,
    address: Option<IpAddr>
}

impl DnsRecord for ARecord {

    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; self.get_length()];

        buf[0] = (self._type.get_code() >> 8) as u8;
        buf[1] = self._type.get_code() as u8;

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

        buf[10..10 + address.len()].copy_from_slice(&address);

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let _type = ((buf[off] as u16) << 8) | (buf[off+1] as u16);
        let dns_class = ((buf[off+2] as u16) << 8) | (buf[off+3] as u16);

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
            _type: Types::get_type_from_code(_type).unwrap(),
            dns_class: Some(DnsClasses::get_class_from_code(dns_class).unwrap()),
            ttl,
            query: None,
            address: Some(address)
        }
    }

    fn length(&self) -> usize {
        todo!()
    }

    fn set_type(&mut self, _type: Types) {
        self._type = _type;
    }

    fn get_type(&self) -> Types {
        self._type
    }

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

    fn set_query(&mut self, query: String) {
        self.query = Some(query);
    }

    fn get_query(&self) -> Option<String> {
        self.query.clone()
    }

    fn get_length(&self) -> usize {
        let len = match self.address.unwrap() {
            IpAddr::V4(address) => {
                address.octets().len()
            }
            IpAddr::V6(address) => {
                address.octets().len()
            }
        };

        len+10
    }
}

impl ARecord {

    pub fn new() -> Self {
        Self {
            _type: Types::A,
            dns_class: None,
            ttl: 0,
            query: None,
            address: None
        }
    }

    pub fn set_address(&mut self, address: IpAddr) {
        self.address = Some(address);
    }

    pub fn get_address(&self) -> Option<IpAddr> {
        self.address
    }
}
