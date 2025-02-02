#[derive(Copy, Clone, Debug)]
pub enum DnsClasses {
    In,
    Cs,
    Ch,
    Hs
}

impl DnsClasses {

    pub fn get_class_from_code(code: u16) -> Result<Self, String> {
        for c in [Self::In, Self::Cs, Self::Ch, Self::Hs] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::In => 1,
            Self::Cs => 2,
            Self::Ch => 3,
            Self::Hs => 4
        }
    }
}
