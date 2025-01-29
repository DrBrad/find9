use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct DnsQuery {
    query: Option<String>,
    _type: Types,
    dns_class: DnsClasses
}

impl Default for DnsQuery {

    fn default() -> Self {
        Self {
            query: None,
            _type: Types::A,
            dns_class: DnsClasses::In
        }
    }
}

impl DnsQuery {

    pub fn new(query: &str, _type: Types, dns_class: DnsClasses) -> Self {
        Self {
            query: Some(query.to_string()),
            _type,
            dns_class
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.get_length()];
        let mut offset = 0;

        let address = pack_domain(self.query.as_ref().unwrap().as_str());
        buf[offset..offset + address.len()].copy_from_slice(&address);
        offset += address.len();

        buf[offset] = (self._type.get_code() >> 8) as u8;
        buf[offset+1] = self._type.get_code() as u8;

        buf[offset+2] = (self.dns_class.get_code() >> 8) as u8;
        buf[offset+3] = self.dns_class.get_code() as u8;

        buf
    }

    pub fn decode(buf: &[u8], off: usize) -> Self {
        let query = unpack_domain(buf, off);
        let off = off+query.len()+2;

        Self {
            query: Some(query),
            _type: Types::get_type_from_code(((buf[off] as u16) << 8) | (buf[off+1] as u16)).unwrap(),
            dns_class: DnsClasses::get_class_from_code(((buf[off+2] as u16) << 8) | (buf[off+3] as u16)).unwrap()
        }
    }

    pub fn set_query(&mut self, query: String) {
        self.query = Some(query);
    }

    pub fn get_query(&self) -> Result<String, String> {
        match self.query {
            Some(ref query) => Ok(query.clone()),
            None => Err("DNS query is not set".to_string())
        }
    }

    pub fn set_type(&mut self, _type: Types) {
        self._type = _type;
    }

    pub fn get_type(&self) -> Types {
        self._type
    }

    pub fn set_dns_class(&mut self, dns_class: DnsClasses) {
        self.dns_class = dns_class;
    }

    pub fn get_dns_class(&self) -> DnsClasses {
        self.dns_class
    }

    pub fn get_length(&self) -> usize {
        self.query.as_ref().unwrap().as_bytes().len()+6
    }
}
