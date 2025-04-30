use std::io;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum OpCodes {
    Query,
    IQuery,
    Status
}

impl OpCodes {

    pub fn from_code(code: u8) -> io::Result<Self> {
        for c in [Self::Query, Self::IQuery, Self::Status] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Couldn't find for code: {}", code)))
    }

    pub fn get_code(&self) -> u8 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2
        }
    }
}
