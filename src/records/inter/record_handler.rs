use std::collections::HashMap;
use crate::records::inter::dns_record::DnsRecord;

pub struct RecordHandler {
    records: HashMap<u16, fn() -> Box<dyn DnsRecord>>
}

impl RecordHandler {

    pub fn new() -> Self {
        Self {
            records: HashMap::new()
        }
    }

    pub fn register_record(&mut self, constructor: fn() -> Box<dyn DnsRecord>) {
        let record = constructor();
        self.records.insert(record.get_type(), constructor);
    }

    pub fn find_record(&self, code: u16) -> Option<&fn() -> Box<dyn DnsRecord>> {
        self.records.get(&code)
    }
}
