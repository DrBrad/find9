
pub struct DnsQuery {

}

impl DnsQuery {

    pub fn new() -> Self {
        Self {

        }
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(&mut self, buf: &[u8], off: usize) {

    }

    pub fn set_query(&mut self, query: String) {

    }

    pub fn get_query(&self) -> String {
        todo!()
    }
}
