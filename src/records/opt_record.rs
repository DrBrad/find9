use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::types::Types;
use crate::records::inter::dns_record::DnsRecord;

#[derive(Clone)]
pub struct OptRecord {
    payload_size: u16,
    ext_rcode: u8,
    edns_version: u8,
    flags: u16,
    options: Vec<u8>
}

impl Default for OptRecord {

    fn default() -> Self {
        Self {
            payload_size: 512,
            ext_rcode: 0,
            edns_version: 0,
            flags: 0x8000,
            options: Vec::new()
        }
    }
}

impl DnsRecord for OptRecord {

    fn encode(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf[0] = (self.get_type().get_code() >> 8) as u8;
        buf[1] = self.get_type().get_code() as u8;

        buf[2] = (self.payload_size >> 8) as u8;
        buf[3] = self.payload_size as u8;

        buf[4] = self.ext_rcode;
        buf[5] = self.edns_version;

        buf[6] = (self.flags >> 8) as u8;
        buf[7] = self.flags as u8;

        buf.extend_from_slice(&self.options);

        buf[8] = (buf.len()-10 >> 8) as u8;
        buf[9] = (buf.len()-10) as u8;

        Ok(buf)
    }

    fn decode(buf: &[u8], off: usize) -> Self {
        let payload_size = ((buf[off] as u16) << 8) | (buf[off+1] as u16);
        let ext_rcode = buf[off+2];
        let edns_version = buf[off+3];
        let flags = ((buf[off+4] as u16) << 8) | (buf[off+5] as u16);

        let length = ((buf[off+6] as u16) << 8) | (buf[off+7] as u16);
        let options = buf[8..8 + length as usize].to_vec();

        Self {
            payload_size,
            ext_rcode,
            edns_version,
            flags,
            options
        }
    }

    fn get_type(&self) -> Types {
        Types::Opt
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
        format!("[RECORD] type {:?} payload_size {}", self.get_type(), self.payload_size)
    }
}

impl OptRecord {

    pub fn new(payload_size: u16, ext_rcode: u8, edns_version: u8, flags: u16, options: Vec<u8>) -> Self {
        Self {
            payload_size,
            ext_rcode,
            edns_version,
            flags,
            options
        }
    }
}
