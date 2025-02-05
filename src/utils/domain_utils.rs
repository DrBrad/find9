use std::collections::HashMap;

pub fn pack_domain(domain: &str, labels_map: &mut HashMap<String, usize>, off: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut off = off;

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
        labels_map.insert(label.clone(), off);
        off += addr.len()+1;
    }

    buf.push(0x00);

    buf
}

pub fn unpack_domain(buf: &[u8], off: usize) -> (String, usize) {
    /*
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

    (builder, length)*/


    let mut builder = String::new();
    let mut pos = off;
    let mut jumped = false; // Track if we followed a pointer
    let mut original_pos = pos; // Store original position for length calculation

    while pos < buf.len() {
        let length = buf[pos] as usize;
        pos += 1;

        if length == 0 {
            break;
        }

        if (length & 0xC0) == 0xC0 {
            // Handle pointer (compression)
            if pos >= buf.len() {
                break;
            }
            let pointer_offset = ((length & 0x3F) << 8) | buf[pos] as usize;
            pos += 1; // Move past pointer byte

            if !jumped {
                original_pos = pos; // Store position after the pointer
            }
            pos = pointer_offset; // Jump to the referenced domain offset
            jumped = true; // Ensure we don't overwrite pos later

        } else {
            // Handle normal labels
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

    let final_pos = if jumped { original_pos } else { pos }; // Ensure correct position
    (builder, final_pos - off) // Correct length calculation
}
