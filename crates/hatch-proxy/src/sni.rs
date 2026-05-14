use thiserror::Error;

#[derive(Debug, Error)]
pub enum SniError {
    #[error("buffer too short: needed {needed}, have {have}")]
    Short { needed: usize, have: usize },
    #[error("not a TLS handshake record")]
    NotHandshake,
    #[error("not a ClientHello")]
    NotClientHello,
    #[error("unsupported TLS version: {0:#06x}")]
    UnsupportedVersion(u16),
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("no SNI extension present")]
    NoSni,
}

pub fn extract_sni(buf: &[u8]) -> Result<String, SniError> {
    if buf.len() < 5 {
        return Err(SniError::Short {
            needed: 5,
            have: buf.len(),
        });
    }
    if buf[0] != 0x16 {
        return Err(SniError::NotHandshake);
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return Err(SniError::Short {
            needed: 5 + record_len,
            have: buf.len(),
        });
    }
    let payload = &buf[5..5 + record_len];
    if payload.is_empty() {
        return Err(SniError::Malformed("empty handshake"));
    }
    if payload[0] != 0x01 {
        return Err(SniError::NotClientHello);
    }
    if payload.len() < 4 {
        return Err(SniError::Malformed("short handshake header"));
    }
    let body_len = (u32::from_be_bytes([0, payload[1], payload[2], payload[3]])) as usize;
    if payload.len() < 4 + body_len {
        return Err(SniError::Short {
            needed: 5 + 4 + body_len,
            have: buf.len(),
        });
    }
    let body = &payload[4..4 + body_len];
    let mut p = 0;
    if body.len() < 2 {
        return Err(SniError::Malformed("missing version"));
    }
    let version = u16::from_be_bytes([body[0], body[1]]);
    if version != 0x0303 && version != 0x0301 && version != 0x0302 {
        return Err(SniError::UnsupportedVersion(version));
    }
    p += 2;

    if body.len() < p + 32 {
        return Err(SniError::Malformed("missing random"));
    }
    p += 32;

    if body.len() <= p {
        return Err(SniError::Malformed("missing session id len"));
    }
    let sid_len = body[p] as usize;
    p += 1;
    if body.len() < p + sid_len {
        return Err(SniError::Malformed("short session id"));
    }
    p += sid_len;

    if body.len() < p + 2 {
        return Err(SniError::Malformed("missing cipher suites len"));
    }
    let suites_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if body.len() < p + suites_len {
        return Err(SniError::Malformed("short cipher suites"));
    }
    p += suites_len;

    if body.len() <= p {
        return Err(SniError::Malformed("missing compression methods len"));
    }
    let comp_len = body[p] as usize;
    p += 1;
    if body.len() < p + comp_len {
        return Err(SniError::Malformed("short compression methods"));
    }
    p += comp_len;

    if body.len() < p + 2 {
        return Err(SniError::NoSni);
    }
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if body.len() < p + ext_total {
        return Err(SniError::Malformed("short extensions"));
    }
    let exts = &body[p..p + ext_total];

    let mut q = 0;
    while q + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let ext_len = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        q += 4;
        if q + ext_len > exts.len() {
            return Err(SniError::Malformed("short extension"));
        }
        if ext_type == 0x0000 {
            let sni_data = &exts[q..q + ext_len];
            if sni_data.len() < 2 {
                return Err(SniError::Malformed("short SNI list"));
            }
            let list_len = u16::from_be_bytes([sni_data[0], sni_data[1]]) as usize;
            if sni_data.len() < 2 + list_len {
                return Err(SniError::Malformed("short SNI list body"));
            }
            let mut r = 2;
            while r + 3 <= 2 + list_len {
                let name_type = sni_data[r];
                let name_len = u16::from_be_bytes([sni_data[r + 1], sni_data[r + 2]]) as usize;
                r += 3;
                if name_type == 0x00 {
                    if r + name_len > sni_data.len() {
                        return Err(SniError::Malformed("short SNI name"));
                    }
                    let name = &sni_data[r..r + name_len];
                    return std::str::from_utf8(name)
                        .map(str::to_string)
                        .map_err(|_| SniError::Malformed("SNI not utf-8"));
                }
                r += name_len;
            }
            return Err(SniError::NoSni);
        }
        q += ext_len;
    }
    Err(SniError::NoSni)
}

pub fn host_matches(allow_exact: &[String], allow_suffix: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if allow_exact.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
        return true;
    }
    allow_suffix.iter().any(|suf| {
        let suf = suf.to_ascii_lowercase();
        host.len() > suf.len() + 1
            && host.ends_with(&suf)
            && host.as_bytes()[host.len() - suf.len() - 1] == b'.'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]);
        body.push(0x01);
        body.push(0x00);

        let mut sni_data = Vec::new();
        let name_bytes = sni.as_bytes();
        let list_body_len = 3 + name_bytes.len();
        sni_data.extend_from_slice(&(list_body_len as u16).to_be_bytes());
        sni_data.push(0x00);
        sni_data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(name_bytes);

        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_data);

        let mut exts = Vec::new();
        exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext);

        body.extend_from_slice(&exts);

        let body_len = body.len() as u32;
        let mut hs = vec![
            0x01,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ];
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn parses_sni() {
        let hello = build_client_hello("api.example.com");
        let host = extract_sni(&hello).unwrap();
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn rejects_non_tls() {
        let buf = b"GET / HTTP/1.1\r\n";
        assert!(matches!(extract_sni(buf), Err(SniError::NotHandshake)));
    }

    #[test]
    fn host_match_suffix() {
        let exact = vec!["api.example.com".to_string()];
        let suffix = vec!["example.com".to_string()];
        assert!(host_matches(&exact, &suffix, "api.example.com"));
        assert!(host_matches(&exact, &suffix, "x.example.com"));
        assert!(!host_matches(&exact, &suffix, "example.com"));
        assert!(!host_matches(&exact, &suffix, "evil.com"));
    }
}
