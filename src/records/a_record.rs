use std::net::IpAddr;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::dns_record::DnsRecord;

pub struct ARecord {
    _type: Types,
    dns_class: Option<DnsClasses>,
    ttl: u32,
    query: Option<String>,
    address: Option<IpAddr>
}

impl DnsRecord for ARecord {

    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn decode(buf: Vec<u8>, off: usize) -> Self {
        todo!()
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

    fn get_query(&self) -> Result<String, String> {
        match self.query {
            Some(ref query) => Ok(query.clone()),
            None => Err("No query string returned".to_string())
        }
    }
}

impl ARecord {

    pub fn new() -> Self {
        Self {
            _type,
            dns_class: None,
            ttl: 0,
            query: None,
            address: None
        }
    }
}
