pub enum ResponseCodes {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused
}

impl ResponseCodes {

    pub fn get_response_code_from_code(code: u16) -> Result<Self, String> {
        for value in [Self::NoError, Self::FormatError, Self::ServerFailure, Self::NameError, Self::NotImplemented, Self::Refused] {
            if value.value() == code {
                return Ok(value);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn value(&self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5
        }
    }
}
