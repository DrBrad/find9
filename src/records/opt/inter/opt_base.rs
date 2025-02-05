use crate::records::opt::inter::opt_codes::OptCodes;

pub trait OptBase {

    fn encode();

    fn decode();

    fn get_opt_code(&self) -> OptCodes;
}
