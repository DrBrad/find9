use std::collections::HashMap;
use std::net::SocketAddr;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::records::inter::dns_record::DnsRecord;
use crate::utils::dns_query::DnsQuery;

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
    answers: Vec<Box<dyn DnsRecord>>,
    name_servers: Vec<Box<dyn DnsRecord>>,
    additional_records: Vec<Box<dyn DnsRecord>>
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
            answers: Vec::new(),
            name_servers: Vec::new(),
            additional_records: Vec::new()
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

        buf[6] = (self.answers.len() >> 8) as u8;
        buf[7] = self.answers.len() as u8;

        buf[8] = (self.name_servers.len() >> 8) as u8;
        buf[9] = self.name_servers.len() as u8;

        buf[10] = (self.additional_records.len() >> 8) as u8;
        buf[11] = self.additional_records.len() as u8;

        let mut query_map = HashMap::new();
        let mut offset = 12;

        for query in &self.queries {
            let q = query.encode();

            buf[offset..offset + q.len()].copy_from_slice(&q);

            let len = q.len();
            query_map.insert(query.get_query().unwrap(), offset);
            offset += len;
        }

        //System.err.println(queries.size()+"  "+answers.size()+"  "+nameServers.size()+"  "+additionalRecords.size());

        for record in &self.answers {
            match query_map.get(&record.get_query().unwrap()) {
                Some(&pointer) => {
                    match record.encode() {
                        Ok(q) => {
                            buf[offset] = (pointer >> 8) as u8;
                            buf[offset+1] = pointer as u8;

                            buf[offset + 2..offset + 2 + q.len()].copy_from_slice(&q);
                            offset += q.len()+2;
                        }
                        Err(_) => {}
                    };
                }
                None => {}
            }
        }

        buf
    }

    pub fn decode(&self, buf: &[u8], off: usize) {

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

    pub fn add_answers(&mut self, answers: Box<dyn DnsRecord>) {
        self.length += answers.get_length()+2;
        self.answers.push(answers);
    }

    /*
    pub fn get_answers(&self) -> Vec<Box<dyn DnsRecord>> {
        self.answers.clone()
    }

    pub fn get_name_servers(&self) -> Vec<Box<dyn DnsRecord>> {
        self.name_servers.clone()
    }

    pub fn get_additional_records(&self) -> Vec<Box<dyn DnsRecord>> {
        self.additional_records.clone()
    }
    */
}
