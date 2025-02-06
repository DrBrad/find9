use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::types::Types;
use crate::records::inter::record_base::DnsRecord;
use crate::utils::domain_utils::{pack_domain, unpack_domain};
use crate::utils::ordered_map::OrderedMap;

#[derive(Clone)]
pub struct NsecRecord {
    dns_class: Option<DnsClasses>,
    cache_flush: bool,
    ttl: u32,
    domain: Option<String>,
    rr_types: Vec<u16>
}

impl Default for NsecRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            cache_flush: false,
            ttl: 0,
            domain: None,
            rr_types: Vec::new()
        }
    }
}

impl DnsRecord for NsecRecord {

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

        buf.extend_from_slice(&pack_domain(self.domain.as_ref().unwrap().as_str(), label_map, off+12));

        /*
        let bitmap_length = self.rr_types.len()*2;
        buf.extend_from_slice(&[(bitmap_length*2 >> 8) as u8, bitmap_length as u8]);

        for rr_type in self.rr_types.clone() {
            buf.extend_from_slice(&[(rr_type >> 8) as u8, rr_type as u8]);
        }
        */
        let mut windows: BTreeMap<u8, Vec<u8>> = BTreeMap::new();

        for rr_type in &self.rr_types {
            let window = (rr_type / 256) as u8;
            let offset = (rr_type % 256) as usize;
            let byte_index = offset / 8;
            let bit_index = 7 - (offset % 8); // Big-endian

            windows.entry(window).or_insert_with(|| vec![0; 32])[byte_index] |= 1 << bit_index;
        }

        let mut result = Vec::new();

        /*
        for (window, bitmap) in windows {
            let trimmed_bitmap = bitmap.iter().rev().skip_while(|&&x| x == 0).collect::<Vec<_>>();
            let length = trimmed_bitmap.len();
            if length > 0 {
                result.push(window);
                result.push(length as u8);
                result.extend(trimmed_bitmap.iter().rev());
            }
        }*/
        for (window, bitmap) in windows {
            // Remove trailing zero bytes from bitmap
            if let Some(non_zero_pos) = bitmap.iter().rposition(|&x| x != 0) {
                let trimmed_bitmap = &bitmap[..=non_zero_pos]; // Slice up to last non-zero byte

                result.push(window);
                result.push(trimmed_bitmap.len() as u8);
                result.extend_from_slice(trimmed_bitmap); // Use extend_from_slice to fix the error
            }
        }



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

        let (domain, length) = unpack_domain(buf, off+8);

        let data_length = off+8+(((buf[off+6] as u16) << 8) | (buf[off+7] as u16)) as usize;
        off += length+8;

        let mut rr_types = Vec::new();

        while off < data_length {
            let window = buf[off];
            let length = buf[off + 1] as usize;

            if off+2+length > data_length {
                break;
            }

            let bitmap = &buf[off + 2..off + 2 + length];

            for (i, &byte) in bitmap.iter().enumerate() {
                for bit in 0..8 {
                    if byte & (1 << (7 - bit)) != 0 {
                        rr_types.push((window as u16) * 256 + (i as u16 * 8 + bit as u16));
                    }
                }
            }

            off += 2+length;
        }

        Self {
            dns_class,
            cache_flush,
            ttl,
            domain: Some(domain),
            rr_types
        }
    }

    fn get_type(&self) -> Types {
        Types::Nsec
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
        format!("[RECORD] type {:?}, class {:?}, domain {}", self.get_type(), self.dns_class.unwrap(), self.domain.as_ref().unwrap())
    }
}

impl NsecRecord {

    pub fn new(dns_classes: DnsClasses, cache_flush: bool, ttl: u32, domain: &str, rr_types: Vec<u16>) -> Self {
        Self {
            dns_class: Some(dns_classes),
            cache_flush,
            ttl,
            domain: Some(domain.to_string()),
            rr_types
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

    pub fn set_domain(&mut self, domain: &str) {
        self.domain = Some(domain.to_string());
    }

    pub fn get_domain(&self) -> Option<String> {
        self.domain.clone()
    }
}
