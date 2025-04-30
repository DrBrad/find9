use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct DnsQuery {
    query: Option<String>,
    _type: Types,
    dns_class: DnsClasses,
    length: usize
}

impl Default for DnsQuery {

    fn default() -> Self {
        Self {
            query: None,
            _type: Types::A,
            dns_class: DnsClasses::In,
            length: 4
        }
    }
}

impl DnsQuery {

    pub fn new(query: &str, _type: Types, dns_class: DnsClasses) -> Self {
        Self {
            query: Some(query.to_string()),
            _type,
            dns_class,
            length: query.len()+6
        }
    }

    pub fn from_bytes(buf: &[u8], off: usize) -> Self {
        let (query, length) = unpack_domain(buf, off);
        let off = off+length;

        let _type = Types::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let dns_class = DnsClasses::from_code(u16::from_be_bytes([buf[off+2], buf[off+3]])).unwrap();

        Self {
            query: Some(query),
            _type,
            dns_class,
            length: length+4
        }
    }

    pub fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Vec<u8> {
        let mut buf = vec![0u8; self.length];

        let address = pack_domain(self.query.as_ref().unwrap().as_str(), label_map, off);
        buf[0..address.len()].copy_from_slice(&address);

        let length = address.len();

        buf.splice(length..length+2, self.dns_class.get_code().to_be_bytes());
        buf.splice(length+2..length+4, self.dns_class.get_code().to_be_bytes());

        buf
    }

    pub fn set_query(&mut self, query: String) {
        self.query = Some(query);
    }

    pub fn get_query(&self) -> Option<&String> {
        self.query.as_ref()
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
        self.length
    }

    pub fn to_string(&self) -> String {
        format!("[QUERY] {}: type {:?}, class {:?}", self.query.as_ref().unwrap(), self._type, self.dns_class)
    }
}
