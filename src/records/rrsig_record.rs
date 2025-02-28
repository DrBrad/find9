use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::{pack_domain_uncompressed, unpack_domain};

#[derive(Clone)]
pub struct RRSigRecord {
    dns_class: Option<DnsClasses>,
    ttl: u32,
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signer_name: Option<String>,
    signature: Vec<u8>
}

impl Default for RRSigRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            type_covered: 0,
            algorithm: 0,
            labels: 0,
            original_ttl: 0,
            signature_expiration: 0,
            signature_inception: 0,
            key_tag: 0,
            signer_name: None,
            signature: Vec::new()
        }
    }
}

impl RecordBase for RRSigRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let dns_class = Some(DnsClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let type_covered = u16::from_be_bytes([buf[off+8], buf[off+9]]);

        let algorithm = buf[off+10];
        let labels = buf[off+11];

        let original_ttl = u32::from_be_bytes([buf[off+12], buf[off+13], buf[off+14], buf[off+15]]);
        let signature_expiration = u32::from_be_bytes([buf[off+16], buf[off+17], buf[off+18], buf[off+19]]);
        let signature_inception = u32::from_be_bytes([buf[off+20], buf[off+21], buf[off+22], buf[off+23]]);
        let key_tag = u16::from_be_bytes([buf[off+24], buf[off+25]]);

        let (signer_name, length) = unpack_domain(buf, off+26);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += length+26;

        let signature = buf[off..data_length].to_vec();

        Self {
            dns_class,
            ttl,
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name: Some(signer_name),
            signature
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 28];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.dns_class.unwrap().get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.splice(10..12, self.type_covered.to_be_bytes());

        buf[12] = self.algorithm;
        buf[13] = self.labels;

        buf.splice(14..18, self.original_ttl.to_be_bytes());
        buf.splice(18..22, self.signature_expiration.to_be_bytes());
        buf.splice(22..26, self.signature_inception.to_be_bytes());
        buf.splice(26..28, self.key_tag.to_be_bytes());

        buf.extend_from_slice(&pack_domain_uncompressed(self.signer_name.as_ref().unwrap()));

        buf.extend_from_slice(&self.signature);

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> Types {
        Types::Rrsig
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

impl RRSigRecord {

    pub fn new(dns_classes: DnsClasses, ttl: u32, type_covered: u16, algorithm: u8, labels: u8, original_ttl: u32, signature_expiration: u32, signature_inception: u32, key_tag: u16, signer_name: &str, signature: &[u8]) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name: Some(signer_name.to_string()),
            signature: signature.to_vec()
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
