#[derive(Copy, Clone, Debug)]
pub enum Types {
    A,
    Aaaa,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Txt,
    Srv,
    Opt,
    Rrsig,
    Nsec,
    Spf,
    Tsig,
    Caa
}

impl Types {

    pub fn get_type_from_code(code: u16) -> Result<Self, String> {
        for c in [Self::A, Self::Aaaa, Self::Ns, Self::Cname, Self::Soa, Self::Ptr, Self::Mx, Self::Txt, Self::Opt, Self::Rrsig, Self::Nsec, Self::Srv, Self::Spf, Self::Tsig, Self::Caa] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Srv => 33,
            Self::Opt => 41,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Spf => 99,
            Self::Tsig => 250,
            Self::Caa => 257
        }
    }
}
