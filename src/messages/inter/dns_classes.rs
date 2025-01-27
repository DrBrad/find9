pub enum DnsClasses {
    In,
    Cs,
    Ch,
    Hs
}

impl DnsClasses {

    pub fn get_class_from_code(code: u16) -> Result<Self, String> {
        for value in [Self::In, Self::Cs, Self::Ch, Self::Hs] {
            if value.value() == code {
                return Ok(value);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn value(&self) -> u16 {
        match self {
            Self::In => 1,
            Self::Cs => 2,
            Self::Ch => 3,
            Self::Hs => 4
        }
    }
}
