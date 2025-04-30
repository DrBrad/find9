use std::io;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum ResponseCodes {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused
}

impl ResponseCodes {

    pub fn from_code(code: u8) -> io::Result<Self> {
        for c in [Self::NoError, Self::FormatError, Self::ServerFailure, Self::NameError, Self::NotImplemented, Self::Refused] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Couldn't find for code: {}", code)))
    }

    pub fn get_code(&self) -> u8 {
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
