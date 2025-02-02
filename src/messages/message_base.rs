use std::collections::HashMap;
use std::net::SocketAddr;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::messages::inter::types::Types;
use crate::records::a_record::ARecord;
use crate::records::aaaa_record::AAAARecord;
use crate::records::cname_record::CNameRecord;
use crate::records::inter::dns_record::DnsRecord;
use crate::utils::dns_query::DnsQuery;
use crate::utils::domain_utils::unpack_domain;

/*
                               1  1  1  1  1  1
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

pub struct MessageBase {
    id: u16,
    op_code: OpCodes,
    response_code: ResponseCodes,
    qr: bool,
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    length: usize,
    origin: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    queries: Vec<DnsQuery>,
    answers: HashMap<String, Box<dyn DnsRecord>>,
    name_servers: HashMap<String, Box<dyn DnsRecord>>,
    additional_records: HashMap<String, Box<dyn DnsRecord>>
}

impl Default for MessageBase {

    fn default() -> Self {
        Self {
            id: 0,
            op_code: OpCodes::Query,
            response_code: ResponseCodes::NoError,
            qr: false,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            length: 12,
            origin: None,
            destination: None,
            queries: Vec::new(),
            answers: HashMap::new(),
            name_servers: HashMap::new(),
            additional_records: HashMap::new()
        }
    }
}

impl MessageBase {

    pub fn new(id: u16) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.length];

        buf[0] = (self.id >> 8) as u8;
        buf[1] = self.id as u8;

        let z = 0;
        let flags = (if self.qr { 0x8000 } else { 0 })
                | ((self.op_code.get_code() & 0x0F) << 11)
                | (if self.authoritative { 0x0400 } else { 0 })
                | (if self.truncated { 0x0200 } else { 0 })
                | (if self.recursion_desired { 0x0100 } else { 0 })
                | (if self.recursion_available { 0x0080 } else { 0 })
                | ((z & 0x07) << 4)
                | (self.response_code.get_code() & 0x0F);

        buf[2] = (flags >> 8) as u8;
        buf[3] = flags as u8;

        buf[4] = (self.queries.len() >> 8) as u8;
        buf[5] = self.queries.len() as u8;

        /*
        buf[6] = (self.answers.len() >> 8) as u8;
        buf[7] = self.answers.len() as u8;

        buf[8] = (self.name_servers.len() >> 8) as u8;
        buf[9] = self.name_servers.len() as u8;

        buf[10] = (self.additional_records.len() >> 8) as u8;
        buf[11] = self.additional_records.len() as u8;
        */

        let mut query_map = HashMap::new();
        let mut offset = 12;

        for query in &self.queries {
            let q = query.encode();

            buf[offset..offset + q.len()].copy_from_slice(&q);

            let len = q.len();
            query_map.insert(query.get_query().unwrap(), offset);
            offset += len;
        }

        //NOT IDEAL AS WHAT ABOUT 2 FOR THE SAME QUERY...

        let mut i = 0;
        for (query, record) in &self.answers {
            match query_map.get(query) {
                Some(&pointer) => {
                    match record.encode() {
                        Ok(q) => {
                            buf[offset] = (pointer >> 8) as u8;
                            buf[offset+1] = pointer as u8;

                            buf[offset + 2..offset + 2 + q.len()].copy_from_slice(&q);
                            offset += q.len()+2;
                            i += 1;
                        }
                        Err(_) => {}
                    };
                }
                None => {}
            }
        }

        buf[6] = (i >> 8) as u8;
        buf[7] = i as u8;

        i = 0;

        //FOR NAME SERVERS

        buf[8] = (i >> 8) as u8;
        buf[9] = i as u8;

        i = 0;

        //FOR ADDITIONAL RECORDS

        buf[10] = (i >> 8) as u8;
        buf[11] = i as u8;

        buf
    }

    pub fn decode(buf: &[u8], off: usize) -> Self {
        let id = ((buf[off] as u16) << 8) | (buf[off+1] as u16);
        let qr = ((buf[off+2] >> 7) & 0x1) == 1;
        let op_code = OpCodes::get_op_from_code(((buf[off+2] >> 3) & 0xf) as u16).unwrap();
        let authoritative = ((buf[off+2] >> 2) & 0x1) == 1;
        let truncated =  ((buf[off+2] >> 1) & 0x1) == 1;
        let recursion_desired = (buf[off+2] & 0x1) == 1;
        let recursion_available = ((buf[off+3] >> 7) & 0x1) == 1;
        let z = (buf[off+3] >> 4) & 0x3;
        let response_code = ResponseCodes::get_response_code_from_code((buf[off+3] & 0xf) as u16).unwrap();
        println!("ID: {} QR: {} OP_CODE: {} AUTH: {} TRUN: {} REC_DES: {} REC_AVA: {} Z: {} RES_CODE: {}",
                id,
                qr,
                op_code.get_code(),
                authoritative,
                truncated,
                recursion_desired,
                recursion_available,
                z,
                response_code.get_code());

        let qd_count = ((buf[off+4] as u16) << 8) | (buf[off+5] as u16);
        let an_count = ((buf[off+6] as u16) << 8) | (buf[off+7] as u16);
        let ns_count = ((buf[off+8] as u16) << 8) | (buf[off+9] as u16);
        let ar_count = ((buf[off+10] as u16) << 8) | (buf[off+11] as u16);

        let mut queries = Vec::new();
        let mut off = 12;

        for i in 0..qd_count {
            let query = DnsQuery::decode(buf, off);
            off += query.get_length();
            queries.push(query);
        }

        let mut answers = HashMap::new();

        for i in 0..an_count {
            let pointer = ((buf[off] as usize & 0x3f) << 8 | buf[off+1] as usize & 0xff) & 0x3fff;
            off += 2;

            answers.insert(unpack_domain(buf, pointer), Self::decode_record(buf, off));
            off += ((buf[off+8] as usize & 0xff) << 8) | (buf[off+9] as usize & 0xff)+10;
        }

        let mut name_servers = HashMap::new();

        for i in 0..ns_count {
            let pointer = ((buf[off] as usize & 0x3f) << 8 | buf[off+1] as usize & 0xff) & 0x3fff;
            off += 2;

            name_servers.insert(unpack_domain(buf, pointer), Self::decode_record(buf, off));
            off += ((buf[off+8] as usize & 0xff) << 8) | (buf[off+9] as usize & 0xff)+10;
        }

        let mut additional_records = HashMap::new();

        for i in 0..ar_count {
            let pointer = ((buf[off] as usize & 0x3f) << 8 | buf[off+1] as usize & 0xff) & 0x3fff;
            off += 2;

            name_servers.insert(unpack_domain(buf, pointer), Self::decode_record(buf, off));
            off += ((buf[off+8] as usize & 0xff) << 8) | (buf[off+9] as usize & 0xff)+10;
        }

        Self {
            id,
            op_code,
            response_code,
            qr,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            length: off,
            origin: None,
            destination: None,
            queries,
            answers,
            name_servers,
            additional_records
        }
    }

    fn decode_record(buf: &[u8], off: usize) -> Box<dyn DnsRecord> {
        match Types::get_type_from_code(((buf[off] as u16) << 8) | (buf[off+1] as u16)).unwrap() {
            Types::A => {
                ARecord::decode(buf, off).dyn_clone()
            }
            Types::Aaaa => {
                AAAARecord::decode(buf, off).dyn_clone()
            }
            Types::Ns => {
                todo!()
            }
            Types::Cname => {
                CNameRecord::decode(buf, off).dyn_clone()
            }
            Types::Soa => {
                todo!()
            }
            Types::Ptr => {
                todo!()
            }
            Types::Mx => {
                todo!()
            }
            Types::Txt => {
                todo!()
            }
            Types::Srv => {
                todo!()
            }
            Types::Caa => {
                todo!()
            }
        }
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn set_qr(&mut self, qr: bool) {
        self.qr = qr;
    }

    pub fn is_qr(&self) -> bool {
        self.qr
    }

    pub fn set_op_code(&mut self, op_code: OpCodes) {
        self.op_code = op_code;
    }

    pub fn get_op_code(&self) -> OpCodes {
        self.op_code.clone()
    }

    pub fn set_origin(&mut self, origin: SocketAddr) {
        self.origin = Some(origin);
    }

    pub fn get_origin(&self) -> Option<SocketAddr> {
        self.origin
    }

    pub fn set_destination(&mut self, destination: SocketAddr) {
        self.destination = Some(destination);
    }

    pub fn get_destination(&self) -> Option<SocketAddr> {
        self.destination
    }

    pub fn set_authoritative(&mut self, authoritative: bool) {
        self.authoritative = authoritative;
    }

    pub fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    pub fn set_truncated(&mut self, truncated: bool) {
        self.truncated = truncated;
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn set_recursion_desired(&mut self, recursion_desired: bool) {
        self.recursion_desired = recursion_desired;
    }

    pub fn is_recursion_desired(&self) -> bool {
        self.recursion_desired
    }

    pub fn set_recursion_available(&mut self, recursion_available: bool) {
        self.recursion_available = recursion_available;
    }

    pub fn is_recursion_available(&self) -> bool {
        self.recursion_available
    }

    pub fn set_response_code(&mut self, response_code: ResponseCodes) {
        self.response_code = response_code;
    }

    pub fn get_response_code(&self) -> ResponseCodes {
        self.response_code
    }

    pub fn total_queries(&self) -> usize {
        self.queries.len()
    }

    pub fn add_query(&mut self, query: DnsQuery) {
        self.length += query.get_length();
        self.queries.push(query);
    }

    pub fn get_queries(&self) -> Vec<DnsQuery> {
        self.queries.clone()
    }

    pub fn add_answers(&mut self, key: &str, value: Box<dyn DnsRecord>) {
        self.length += value.get_length()+2;
        self.answers.insert(key.to_string(), value);
    }

    pub fn get_answers(&self) -> &HashMap<String, Box<dyn DnsRecord>> {
        &self.answers
    }

    pub fn get_name_servers(&self) -> &HashMap<String, Box<dyn DnsRecord>> {
        &self.name_servers
    }

    pub fn get_additional_records(&self) -> &HashMap<String, Box<dyn DnsRecord>> {
        &self.additional_records
    }
}
