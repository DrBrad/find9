pub enum OpCodes {
    Query,
    IQuery,
    Status
}

impl OpCodes {

    pub fn get_op_from_code(code: u16) -> Result<Self, String> {
        for value in [Self::Query, Self::IQuery, Self::Status] {
            if value.value() == code {
                return Ok(value);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn value(&self) -> u16 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2
        }
    }
}
