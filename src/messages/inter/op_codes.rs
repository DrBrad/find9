pub enum OpCodes {
    Query,
    IQuery,
    Status
}

impl OpCodes {

    pub fn get_op_from_code(code: u16) -> Result<Self, String> {
        for c in [Self::Query, Self::IQuery, Self::Status] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2
        }
    }
}
