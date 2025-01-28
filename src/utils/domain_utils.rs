
pub fn pack_domain(domain: &str) -> Vec<u8> {
    let mut buf = vec![0u8; domain.len()+2];
    let mut offset = 0;

    for part in domain.split('.') {
        let addr = part.as_bytes();
        buf[offset] = addr.len() as u8;
        //COPY
        offset += addr.len()+1;
    }

    buf
}

pub fn unpack_domain(buf: &[u8], off: usize) -> Vec<u8> {
    todo!()
}
