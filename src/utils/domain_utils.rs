use std::collections::{HashMap, HashSet};

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

pub fn pack_domain_with_pointers(domain: &str, labels_map: &HashMap<String, usize>) -> Vec<u8> {
    let mut buf = Vec::new();//vec![0u8; domain.len()+2];
    let mut offset = 0;

    let parts: Vec<&str> = domain.split('.').collect();

    for i in 0..parts.len() {
        let label = parts[i..].join(".");

        if let Some(&ptr_offset) = labels_map.get(&label) {//&parts.get(i).unwrap().to_string()) {
            buf.extend_from_slice(&[(0xC0 | (ptr_offset >> 8)) as u8, (ptr_offset & 0xFF) as u8]);
            return buf;
        }

        let addr = parts.get(i).unwrap().as_bytes();
        buf.push(addr.len() as u8);
        buf.extend_from_slice(addr);
    }

    //buf[offset] = 0x00;

    buf
}

pub fn unpack_domain(buf: &[u8], off: usize) -> (String, usize) {
    let mut builder = String::new();
    let mut pos = off;

    while pos < buf.len() {
        let length = buf[pos] as usize;
        pos += 1;

        if length == 0 {
            break;
        }

        if (length & 0xc0) == 0xc0 {
            if pos >= buf.len() {
                break;
            }
            pos = ((length & 0x3f) << 8) | (buf[pos] as usize);

        } else {
            if !builder.is_empty() {
                builder.push('.');
            }

            if pos + length > buf.len() {
                break;
            }

            let label = &buf[pos..pos + length];
            builder.push_str(&String::from_utf8_lossy(label));
            pos += length;
        }
    }

    let length = builder.len()+2;

    (builder, length)

    /*
    let mut name = String::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut seen_offsets = HashSet::new();

    while pos < buffer.len() {
        if seen_offsets.contains(&pos) {
            break;
        }
        seen_offsets.insert(pos);

        let len = buffer[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }

        if len & 0xC0 == 0xC0 {
            let ptr_offset = (((len as u16 & 0x3F) << 8) | buffer[pos + 1] as u16) as usize;
            pos += 2;
            return (name, pos - offset);

        } else {
            pos += 1;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&buffer[pos..pos + len]));
            pos += len;
        }
    }

    (name, pos - offset)
    */
}
