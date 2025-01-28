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

        for query in self.queries {
            let q = query.encode();

            //System.arraycopy(q, 0, buf, offset, q.length);

            let len = q.len();
            query_map.insert(query.get_query(), offset);
            offset += len;
        }

        //System.err.println(queries.size()+"  "+answers.size()+"  "+nameServers.size()+"  "+additionalRecords.size());

        for record in self.answers {
            match *query_map.get(&record.get_query().unwrap()) {
                Some(pointer) => {
                    buf[offset] = (pointer >> 8) as u8;
                    buf[offset+1] = pointer as u8;
                }
                None => {}
            }

            let q = record.encode();
            //System.arraycopy(q, 0, buf, offset+2, q.length);
            offset += q.len()+2;
        }

        buf
    }

    pub fn decode(&self, buf: &[u8], off: usize) {

    }
}
