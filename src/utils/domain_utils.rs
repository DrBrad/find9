
pub fn pack_domain(domain: &str) -> Vec<u8> {
    let mut buf = vec![0u8; domain.len()+2];
    let mut offset = 0;

    for part in domain.split('.') {
        let addr = part.as_bytes();
        buf[offset] = addr.len() as u8;
        buf[offset + 1..offset + 1 + addr.len()].copy_from_slice(addr);
        offset += addr.len()+1;
    }

    buf[offset] = 0x00;

    buf
}

pub fn unpack_domain(buf: &[u8], off: usize) -> String {
    let mut builder = String::new();
    let mut off = off;

    while off < buf.len() {
        let length = buf[off] as usize;
        off += 1;

        if length == 0 {
            break;
        }

        if (length & 0xc0) == 0xc0 {
            if off >= buf.len() {
                break;
            }
            off = ((length & 0x3f) << 8) | (buf[off] as usize);

        } else {
            if !builder.is_empty() {
                builder.push('.');
            }

            if off + length > buf.len() {
                break;
            }

            let label = &buf[off..off + length];
            builder.push_str(&String::from_utf8_lossy(label));
            off += length;
        }
    }

    builder
}
