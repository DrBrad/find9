use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::messages::inter::types::Types;
use crate::records::a_record::ARecord;
use crate::records::aaaa_record::AAAARecord;
use crate::records::cname_record::CNameRecord;
use crate::records::dnskey_record::DNSKeyRecord;
use crate::records::https_record::HttpsRecord;
use crate::records::inter::record_base::RecordBase;
use crate::records::mx_record::MxRecord;
use crate::records::ns_record::NsRecord;
use crate::records::nsec_record::NsecRecord;
use crate::records::opt_record::OptRecord;
use crate::records::ptr_record::PtrRecord;
use crate::records::rrsig_record::RRSigRecord;
use crate::records::soa_record::SoaRecord;
use crate::records::srv_record::SrvRecord;
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
    answers: OrderedMap<String, Vec<Box<dyn RecordBase>>>,
    name_servers: OrderedMap<String, Vec<Box<dyn RecordBase>>>,
    additional_records: OrderedMap<String, Vec<Box<dyn RecordBase>>>
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

    pub fn from_bytes(buf: &[u8], off: usize) -> io::Result<Self> {
        let id = u16::from_be_bytes([buf[off], buf[off+1]]);

        let flags = u16::from_be_bytes([buf[off+2], buf[off+3]]);

        let qr = (flags & 0x8000) != 0;
        let op_code = OpCodes::from_code(((flags >> 11) & 0x0F) as u8)?;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        //let z = (flags & 0x0040) != 0;
        let authenticated_data = (flags & 0x0020) != 0;
        let checking_disabled = (flags & 0x0010) != 0;
        let response_code = ResponseCodes::from_code((flags & 0x000F) as u8)?;

        /*
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
                */

        let qd_count = u16::from_be_bytes([buf[off+4], buf[off+5]]);
        let an_count = u16::from_be_bytes([buf[off+6], buf[off+7]]);
        let ns_count = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        let ar_count = u16::from_be_bytes([buf[off+10], buf[off+11]]);

        //println!("{} {} {} {}", qd_count, an_count, ns_count, ar_count);

        let mut queries = Vec::new();
        let mut off = 12;

        for i in 0..qd_count {
            let query = DnsQuery::from_bytes(buf, off);
            off += query.get_length();
            //println!("{}", query.to_string());
            queries.push(query);
        }

        let (answers, length) = Self::records_from_bytes(buf, off, an_count);
        off += length;

        let (name_servers, length) = Self::records_from_bytes(buf, off, ns_count);
        off += length;

        let (additional_records, length) = Self::records_from_bytes(buf, off, ar_count);
        off += length;

        Ok(Self {
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
        })
    }

    fn records_from_bytes(buf: &[u8], off: usize, count: u16) -> (OrderedMap<String, Vec<Box<dyn RecordBase>>>, usize) {
        let mut records: OrderedMap<String, Vec<Box<dyn RecordBase>>> = OrderedMap::new();
        let mut pos = off;

        for _ in 0..count {
            let domain = match buf[pos] {
                0 => {
                    pos += 1;
                    String::new()
                }
                _ => {
                    let (domain, length) = unpack_domain(buf, pos);
                    pos += length;
                    domain
                }
            };

            let record = match Types::from_code(u16::from_be_bytes([buf[pos], buf[pos+1]])).unwrap() {
                Types::A => {
                    ARecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Aaaa => {
                    AAAARecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Ns => {
                    NsRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Cname => {
                    CNameRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Soa => {
                    SoaRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Ptr => {
                    PtrRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Mx => {
                    MxRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Txt => {
                    TxtRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Srv => {
                    SrvRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Opt => {
                    OptRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Rrsig => {
                    RRSigRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Nsec => {
                    NsecRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::DnsKey => {
                    DNSKeyRecord::from_bytes(buf, pos+2).dyn_clone()
                }
                Types::Https => {
                    HttpsRecord::from_bytes(buf, pos+2).dyn_clone()
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
                _ => {
                    todo!()
                }
            };
            //println!("{}: {}", domain, record.to_string());

            records.entry(domain).or_insert_with(Vec::new).push(record);
            pos += 10+u16::from_be_bytes([buf[pos+8], buf[pos+9]]) as usize;
        }

        (records, pos-off)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 12];//self.length];

        buf.splice(0..2, self.id.to_be_bytes());

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

        buf.splice(2..4, flags.to_be_bytes());

        buf.splice(4..6, (self.queries.len() as u16).to_be_bytes());

        let mut label_map = HashMap::new();
        let mut off = 12;

        for query in &self.queries {
            let q = query.to_bytes(&mut label_map, off);
            buf.extend_from_slice(&q);
            off += q.len();
        }

        let (answers, i) = Self::records_to_bytes(off, &self.answers, &mut label_map);
        buf.extend_from_slice(&answers);

        buf.splice(6..8, i.to_be_bytes());



        let (answers, i) = Self::records_to_bytes(off, &self.name_servers, &mut label_map);
        buf.extend_from_slice(&answers);

        buf.splice(8..10, i.to_be_bytes());



        let (answers, i) = Self::records_to_bytes(off, &self.additional_records, &mut label_map);
        buf.extend_from_slice(&answers);

        buf.splice(10..12, i.to_be_bytes());

        buf
    }

    fn records_to_bytes(off: usize, records: &OrderedMap<String, Vec<Box<dyn RecordBase>>>, label_map: &mut HashMap<String, usize>) -> (Vec<u8>, u16) {
        let mut buf = Vec::new();
        let mut i = 0;
        let mut off = off;

        for (query, records) in records.iter() {
            for record in records {
                match record.to_bytes(label_map, off) {
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

    pub fn add_answers(&mut self, query: &str, record: Box<dyn RecordBase>) {
        if self.answers.contains_key(&query.to_string()) {
            self.answers.get_mut(&query.to_string()).unwrap().push(record);
            return;
        }

        self.answers.insert(query.to_string(), vec![record]);
    }

    pub fn get_name_servers(&self) -> &OrderedMap<String, Vec<Box<dyn RecordBase>>> {
        &self.name_servers
    }

    pub fn get_additional_records(&self) -> &OrderedMap<String, Vec<Box<dyn RecordBase>>> {
        &self.additional_records
    }
}
