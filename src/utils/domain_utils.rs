use std::collections::HashMap;

pub fn pack_domain_uncompressed(domain: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    let parts: Vec<&str> = domain.split('.').collect();

    for part in parts {
        buf.push(part.len() as u8);
        buf.extend(part.as_bytes());
    }

    buf.push(0x00);

    buf
}

pub fn pack_domain(domain: &str, labels_map: &mut HashMap<String, usize>, off: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut off = off;

    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() < 2 {
        buf.push(0x00);
        return buf;
    }

    for i in 0..parts.len() {
        let label = parts[i..].join(".");

        if let Some(&ptr_offset) = labels_map.get(&label) {
            buf.extend_from_slice(&[(0xC0 | (ptr_offset >> 8)) as u8, (ptr_offset & 0xFF) as u8]);
            return buf;
        }

        let addr = parts.get(i).unwrap().as_bytes();
        buf.push(addr.len() as u8);
        buf.extend_from_slice(addr);
        labels_map.insert(label.clone(), off);
        off += addr.len()+1;
    }

    buf.push(0x00);

    buf
}

pub fn unpack_domain(buf: &[u8], off: usize) -> (String, usize) {
    let mut builder = String::new();
    let mut pos = off;
    let mut jumped = false;
    let mut original_pos = pos;

    while pos < buf.len() {
        let length = buf[pos] as usize;
        pos += 1;

        if length == 0 {
            break;
        }

        if (length & 0xC0) == 0xC0 {
            if pos >= buf.len() {
                break;
            }
            let pointer_offset = ((length & 0x3F) << 8) | buf[pos] as usize;
            pos += 1;

            if !jumped {
                original_pos = pos;
            }
            pos = pointer_offset;
            jumped = true;

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

    let final_pos = if jumped { original_pos } else { pos };
    (builder, final_pos - off)
}
