use std::collections::HashMap;
use std::net::SocketAddr;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::messages::inter::types::Types;
use crate::records::a_record::ARecord;
use crate::records::aaaa_record::AAAARecord;
use crate::records::cname_record::CNameRecord;
use crate::records::inter::record_base::DnsRecord;
use crate::records::mx_record::MxRecord;
use crate::records::ns_record::NsRecord;
use crate::records::opt_record::OptRecord;
use crate::records::ptr_record::PtrRecord;
use crate::records::soa_record::SoaRecord;
use crate::records::txt_record::TxtRecord;
use crate::utils::dns_query::DnsQuery;
use crate::utils::domain_utils::{pack_domain, unpack_domain};
use crate::utils::ordered_map::OrderedMap;
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
    authenticated_data: bool,
    checking_disabled: bool,
    //length: usize,
    origin: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    queries: Vec<DnsQuery>,
    answers: OrderedMap<String, Vec<Box<dyn DnsRecord>>>,
    name_servers: OrderedMap<String, Vec<Box<dyn DnsRecord>>>,
    additional_records: OrderedMap<String, Vec<Box<dyn DnsRecord>>>
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
            authenticated_data: false,
            checking_disabled: false,
            //length: 12,
            origin: None,
            destination: None,
            queries: Vec::new(),
            answers: OrderedMap::new(),
            name_servers: OrderedMap::new(),
            additional_records: OrderedMap::new()
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
        let mut buf = vec![0u8; 12];//self.length];

        buf[0] = (self.id >> 8) as u8;
        buf[1] = self.id as u8;

        let flags = (if self.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.op_code as u16 & 0x0F) << 11) |  // Opcode
            (if self.authoritative { 0x0400 } else { 0 }) |  // AA bit
            (if self.truncated { 0x0200 } else { 0 }) |  // TC bit
            (if self.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.response_code as u16 & 0x000F);  // RCODE

        buf[2] = (flags >> 8) as u8;
        buf[3] = flags as u8;

        buf[4] = (self.queries.len() >> 8) as u8;
        buf[5] = self.queries.len() as u8;

        let mut label_map = HashMap::new();
        let mut offset = 12;

        for query in &self.queries {
            let q = query.encode(&mut label_map, offset);

            buf.extend_from_slice(&q);
            //buf[offset..offset + q.len()].copy_from_slice(&q);

            let len = q.len();
            // label_map.insert(query.get_query().unwrap(), offset);
            offset += len;
        }

        let (answers, i) = Self::encode_records(offset, &self.answers, &mut label_map);
        buf.extend_from_slice(&answers);

        buf[6] = (i >> 8) as u8;
        buf[7] = i as u8;



        let (answers, i) = Self::encode_records(offset, &self.name_servers, &mut label_map);
        buf.extend_from_slice(&answers);

        buf[8] = (i >> 8) as u8;
        buf[9] = i as u8;



        let (answers, i) = Self::encode_records(offset, &self.additional_records, &mut label_map);
        buf.extend_from_slice(&answers);

        buf[10] = (i >> 8) as u8;
        buf[11] = i as u8;

        buf
    }

    pub fn decode(buf: &[u8], off: usize) -> Self {
        let id = ((buf[off] as u16) << 8) | (buf[off+1] as u16);

        let flags = ((buf[off+2] as u16) << 8) | (buf[off+3] as u16);

        let qr = (flags & 0x8000) != 0;
        let op_code = OpCodes::get_op_from_code(((flags >> 11) & 0x0F) as u8).unwrap();
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        //let z = (flags & 0x0040) != 0;
        let authenticated_data = (flags & 0x0020) != 0;
        let checking_disabled = (flags & 0x0010) != 0;
        let response_code = ResponseCodes::get_response_code_from_code((flags & 0x000F) as u8).unwrap();

        println!("ID: {} QR: {} OP_CODE: {:?} AUTH: {} TRUN: {} REC_DES: {} REC_AVA: {} AUTH_DAT: {} CHK_DIS: {} RES_CODE: {:?}",
                id,
                qr,
                op_code,
                authoritative,
                truncated,
                recursion_desired,
                recursion_available,
                authenticated_data,
                checking_disabled,
                response_code);

        let qd_count = ((buf[off+4] as u16) << 8) | (buf[off+5] as u16);
        let an_count = ((buf[off+6] as u16) << 8) | (buf[off+7] as u16);
        let ns_count = ((buf[off+8] as u16) << 8) | (buf[off+9] as u16);
        let ar_count = ((buf[off+10] as u16) << 8) | (buf[off+11] as u16);

        println!("{} {} {} {}", qd_count, an_count, ns_count, ar_count);

        let mut queries = Vec::new();
        let mut off = 12;

        for i in 0..qd_count {
            let query = DnsQuery::decode(buf, off);
            off += query.get_length();
            println!("{}", query.to_string());
            queries.push(query);
        }

        let (answers, length) = Self::decode_records(buf, off, an_count);
        off += length;

        let (name_servers, length) = Self::decode_records(buf, off, ns_count);
        off += length;

        let (additional_records, length) = Self::decode_records(buf, off, ar_count);
        off += length;

        Self {
            id,
            op_code,
            response_code,
            qr,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authenticated_data,
            checking_disabled,
            //length: off,
            origin: None,
            destination: None,
            queries,
            answers,
            name_servers,
            additional_records
        }
    }

    fn encode_records(off: usize, records: &OrderedMap<String, Vec<Box<dyn DnsRecord>>>, label_map: &mut HashMap<String, usize>) -> (Vec<u8>, u16) {
        let mut buf = Vec::new();
        let mut i = 0;
        let mut off = off;

        for (query, records) in records.iter() {
            for record in records {
                match record.encode(label_map, off) {
                    Ok(e) => {
                        //println!("{}: {}", query, record.to_string());
                        match query.len() {
                            0 => {
                                buf.push(0);
                            }
                            _ => {
                                let eq = pack_domain(query, label_map, off);
                                buf.extend_from_slice(&eq);
                                off += eq.len();
                            }
                        }

                        buf.extend_from_slice(&e);
                        off += e.len();
                    }
                    Err(_) => {}
                }
                i += 1;
            }
        }

        (buf, i)
    }

    fn decode_records(buf: &[u8], off: usize, count: u16) -> (OrderedMap<String, Vec<Box<dyn DnsRecord>>>, usize) {
        let mut records: OrderedMap<String, Vec<Box<dyn DnsRecord>>> = OrderedMap::new();
        let mut pos = off;

        for _ in 0..count {
            let mut domain = String::new();

            match buf[pos] {
                0 => {
                    pos += 1;
                }
                _ => {
                    let pointer = ((buf[pos] as usize & 0x3f) << 8 | buf[pos+1] as usize & 0xff) & 0x3fff;
                    (domain, _) = unpack_domain(buf, pointer);
                    pos += 2;
                }
            }

            let record = match Types::get_type_from_code(((buf[pos] as u16) << 8) | (buf[pos+1] as u16)).unwrap() {
                Types::A => {
                    ARecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Aaaa => {
                    AAAARecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Ns => {
                    NsRecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Cname => {
                    CNameRecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Soa => {
                    SoaRecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Ptr => {
                    PtrRecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Mx => {
                    MxRecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Txt => {
                    TxtRecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Srv => {
                    todo!()
                }
                Types::Opt => {
                    OptRecord::decode(buf, pos+2).dyn_clone()
                }
                Types::Rrsig => {
                    todo!()
                }
                Types::Nsec => {
                    todo!()
                }
                Types::DnsKey => {
                    todo!()
                }
                Types::Spf => {
                    todo!()
                }
                Types::Tsig => {
                    todo!()
                }
                Types::Caa => {
                    todo!()
                }
            };
            println!("{}: {}", domain, record.to_string());

            records.entry(domain).or_insert_with(Vec::new).push(record);
            pos += ((buf[pos+8] as usize & 0xff) << 8) | (buf[pos+9] as usize & 0xff)+10;
        }

        (records, pos-off)
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
        self.queries.push(query);
    }

    pub fn get_queries(&self) -> Vec<DnsQuery> {
        self.queries.clone()
    }

    pub fn add_answers(&mut self, query: &str, record: Box<dyn DnsRecord>) {
        if self.answers.contains_key(&query.to_string()) {
            self.answers.get_mut(&query.to_string()).unwrap().push(record);
            return;
        }

        //self.answers.push(record);
    }

    /*
    pub fn get_answers(&self) -> &Vec<Box<dyn DnsRecord>> {
        &self.answers
    }*/

    pub fn get_name_servers(&self) -> &OrderedMap<String, Vec<Box<dyn DnsRecord>>> {
        &self.name_servers
    }

    pub fn get_additional_records(&self) -> &OrderedMap<String, Vec<Box<dyn DnsRecord>>> {
        &self.additional_records
    }
}
