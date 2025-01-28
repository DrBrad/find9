use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;

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
        todo!()
    }

    pub fn decode(&mut self, buf: &[u8], off: usize) {

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

    pub fn get_length(&self) -> usize {
        self.query.as_ref().unwrap().as_bytes().len()+6
    }
}
