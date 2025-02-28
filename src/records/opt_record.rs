use std::any::Any;
use std::collections::HashMap;
use crate::messages::inter::types::Types;
use crate::records::inter::opt_codes::OptCodes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::ordered_map::OrderedMap;

#[derive(Clone)]
pub struct OptRecord {
    payload_size: u16,
    ext_rcode: u8,
    edns_version: u8,
    flags: u16,
    options: OrderedMap<OptCodes, Vec<u8>>
}

impl Default for OptRecord {

    fn default() -> Self {
        Self {
            payload_size: 512,
            ext_rcode: 0,
            edns_version: 0,
            flags: 0x8000,
            options: OrderedMap::new()
        }
    }
}

impl RecordBase for OptRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let payload_size = u16::from_be_bytes([buf[off], buf[off+1]]);
        let ext_rcode = buf[off+2];
        let edns_version = buf[off+3];
        let flags = u16::from_be_bytes([buf[off+4], buf[off+5]]);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        let mut off = off+8;
        let mut options = OrderedMap::new();

        while off < data_length {
            let opt_code = OptCodes::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            options.insert(opt_code, buf[off + 4..off + 4 + length].to_vec());

            off += 4+length;
        }

        Self {
            payload_size,
            ext_rcode,
            edns_version,
            flags,
            options
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.payload_size.to_be_bytes());

        buf[4] = self.ext_rcode;
        buf[5] = self.edns_version;

        buf.splice(6..8, self.flags.to_be_bytes());

        for (code, option) in self.options.iter() {
            buf.extend_from_slice(&code.get_code().to_be_bytes());
            buf.extend_from_slice(&(option.len() as u16).to_be_bytes());
            buf.extend_from_slice(&option);
        }

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
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
        format!("[RECORD] type {:?} payload_size {}", self.get_type(), self.payload_size)
    }
}

impl OptRecord {

    pub fn new(payload_size: u16, ext_rcode: u8, edns_version: u8, flags: u16) -> Self {
        Self {
            payload_size,
            ext_rcode,
            edns_version,
            flags,
            options: OrderedMap::new()
        }
    }
}
