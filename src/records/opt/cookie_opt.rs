use crate::records::opt::inter::opt_base::OptBase;
use crate::records::opt::inter::opt_codes::OptCodes;

pub struct CookieOpt {
    cookie: Vec<u8>
}

impl OptBase for CookieOpt {

    fn encode() {
        todo!()
    }

    fn decode() {
        todo!()
    }

    fn get_opt_code(&self) -> OptCodes {
        OptCodes::Cookie
    }
}

impl CookieOpt {

    pub fn new() -> Self {
        Self {
            cookie: Vec::new()
        }
    }
}
