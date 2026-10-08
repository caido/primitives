use crate::{
    abnf::*,
    message_head::header_map::{
        HeaderStr, HeaderVersion, Hmap, one::OneHeader,
    },
    version::Version,
};
use bytes::{Bytes, BytesMut};

#[derive(Clone, Eq, Debug)]
pub struct Header {
    key: Bytes,
    value: Bytes,
    is_removed: bool,
    is_sensitive: bool,
}

// Encoding policy does not change field equality.
impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
            && self.value == other.value
            && self.is_removed == other.is_removed
    }
}

impl Header {
    pub fn new(key: Bytes, value: Bytes) -> Self {
        Header {
            key,
            value,
            is_removed: false,
            is_sensitive: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.key.is_empty() && self.value.is_empty() && self.is_removed
    }

    /// Whether this field occurrence must use a never-indexed representation
    /// when encoded with HPACK. Defaults to false and does not affect equality.
    pub fn is_sensitive(&self) -> bool {
        self.is_sensitive
    }

    /// Sets the HPACK sensitivity policy for this occurrence only.
    /// Byte mutations and clearing the field preserve this flag.
    pub fn set_sensitive(&mut self, sensitive: bool) {
        self.is_sensitive = sensitive;
    }

    /// Returns the field bytes, discarding sensitivity metadata.
    /// Use [`Self::into_parts`] to preserve the encoding policy.
    pub fn into_inner(self) -> (Bytes, Bytes) {
        (self.key, self.value)
    }

    /// Returns the field bytes and per-occurrence sensitivity flag.
    /// Like [`Self::into_inner`], this does not return the removal state.
    pub fn into_parts(self) -> (Bytes, Bytes, bool) {
        (self.key, self.value, self.is_sensitive)
    }
}

impl HeaderStr for Header {
    fn key_as_str(&self) -> Option<&str> {
        (!self.is_removed).then(|| str::from_utf8(&self.key).ok()).flatten()
    }

    fn value_as_str(&self) -> Option<&str> {
        (!self.is_removed).then(|| str::from_utf8(&self.value).ok()).flatten()
    }
}

impl HeaderVersion for Header {
    fn version(&self) -> crate::version::Version {
        Version::H2
    }

    fn is_one_one(&self) -> bool {
        false
    }

    fn is_two(&self) -> bool {
        true
    }
}

impl Hmap for Header {
    fn key_as_ref(&self) -> &[u8] {
        &self.key
    }

    fn value_as_ref(&self) -> &[u8] {
        &self.value
    }

    fn change_key(&mut self, key: &[u8]) {
        self.key = Bytes::from(key.to_owned());
    }

    fn change_value(&mut self, value: &[u8]) {
        self.value = Bytes::from(value.to_owned());
    }

    fn clear(&mut self) {
        self.key.clear();
        self.value.clear();
        self.is_removed = true;
    }

    fn len(&self) -> usize {
        self.key.len() + self.value.len()
    }

    fn truncate_value(&mut self, pos: usize) {
        self.value.truncate(pos)
    }
}

fn split_header(header: &[u8]) -> (&[u8], &[u8]) {
    let Some(p) = header.iter().position(|&b| b == COLON) else {
        return (header, b"");
    };

    let value = &header
        .get(p + 1..)
        .and_then(|v| {
            if v.first() == Some(&SP) {
                v.get(1..)
            } else {
                Some(v)
            }
        })
        .map(|v| v.trim_ascii_end())
        .unwrap_or_default();
    (&header[..p], value)
}

fn check_utf8_and_to_lowercase_bytes(src: &[u8]) -> Bytes {
    match str::from_utf8(src) {
        Ok(s) => to_lowercase_bytes(s.as_bytes()),
        Err(e) => {
            eprintln!("h2 not valid utf| {}", e);
            to_lowercase_bytes(String::from_utf8_lossy(src).as_bytes())
        }
    }
}

impl<T, E> From<(T, E)> for Header
where
    T: AsRef<[u8]>,
    E: AsRef<[u8]>,
{
    fn from((key, value): (T, E)) -> Self {
        Header {
            key: check_utf8_and_to_lowercase_bytes(key.as_ref()),
            value: Bytes::from(value.as_ref().to_owned()),
            is_removed: false,
            is_sensitive: false,
        }
    }
}

impl From<&[u8]> for Header {
    fn from(hdr: &[u8]) -> Self {
        let (key, val) = split_header(hdr);
        Header {
            key: check_utf8_and_to_lowercase_bytes(key),
            value: Bytes::copy_from_slice(val),
            is_removed: false,
            is_sensitive: false,
        }
    }
}

fn to_lowercase_bytes(src: &[u8]) -> Bytes {
    let mut key = BytesMut::from(src);
    key.make_ascii_lowercase();
    key.freeze()
}

impl From<&str> for Header {
    fn from(hdr: &str) -> Self {
        let (key, value) = hdr
            .split_once(COLON as char)
            .map(|(k, v)| (k, v.trim()))
            .unwrap_or((hdr, ""));
        Header {
            key: to_lowercase_bytes(key.as_bytes()),
            value: Bytes::from(value.as_bytes().to_owned()),
            is_removed: false,
            is_sensitive: false,
        }
    }
}

impl From<Header> for OneHeader {
    fn from(two: Header) -> OneHeader {
        let mut key = BytesMut::from(two.key);
        key.extend_from_slice(HEADER_FS);
        let mut value = BytesMut::from(two.value);
        value.extend_from_slice(CRLF);
        OneHeader::new(key, value)
    }
}

#[cfg(test)]
mod tests {
    use crate::const_headers::CONTENT_TYPE;

    use super::*;
    const CT: &str = "content-type";

    #[test]
    fn sensitivity_defaults_to_false() {
        let headers = [
            Header::new(
                Bytes::from_static(b"key"),
                Bytes::from_static(b"value"),
            ),
            Header::from(("key", "value")),
            Header::from(b"key: value".as_slice()),
            Header::from("key: value"),
            Header::from(OneHeader::from(("key", "value"))),
        ];
        assert!(headers.iter().all(|h| !h.is_sensitive()));
    }

    #[test]
    fn sensitivity_preserves_bytes_and_does_not_affect_equality() {
        let plain = Header::from((b"key".as_slice(), b"\xff\x80".as_slice()));
        let mut sensitive = plain.clone();
        sensitive.set_sensitive(true);
        assert!(sensitive.is_sensitive());
        assert!(!plain.is_sensitive());
        assert_eq!(plain, sensitive);
        assert_eq!(sensitive.key_as_ref(), b"key");
        assert_eq!(sensitive.value_as_ref(), b"\xff\x80");
        sensitive.set_sensitive(false);
        assert!(!sensitive.is_sensitive());
    }

    #[test]
    fn sensitivity_survives_mutation_and_clear() {
        let mut header = Header::from(("key", "value"));
        header.set_sensitive(true);
        header.change_key(b"other");
        header.change_value(b"changed");
        header.truncate_value(3);
        assert!(header.is_sensitive());
        assert_eq!(header.value_as_ref(), b"cha");
        header.clear();
        assert!(header.is_empty());
        assert!(header.is_sensitive());
        assert_eq!(header.key_as_str(), None);
        assert_eq!(header.value_as_str(), None);
        assert_ne!(header, Header::from(("", "")));
    }

    #[test]
    fn sensitivity_survives_map_operations() {
        use crate::message_head::header_map::HeaderMap;

        let mut map = HeaderMap::new();
        map.insert("key", "value");
        map.insert("key", "value");
        map.iter_mut().nth(1).unwrap().set_sensitive(true);
        let flags = |map: &HeaderMap| {
            map.iter().map(Header::is_sensitive).collect::<Vec<_>>()
        };
        assert_eq!(flags(&map), vec![false, true]);
        let mut copied = HeaderMap::new();
        copied.extend(map.clone());
        assert_eq!(map, copied);
        assert_eq!(flags(&copied), vec![false, true]);
        let filtered: Vec<_> =
            copied.clone().into_iter().filter(Header::is_sensitive).collect();
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].is_sensitive());
        assert!(copied.remove_header(("key", "value")));
        assert!(copied.iter().next().unwrap().is_empty());
        assert_eq!(flags(&copied), vec![false, true]);
        assert!(copied.remove_header(("key", "value")));
        assert!(copied.iter().nth(1).unwrap().is_empty());
        assert_eq!(flags(&copied), vec![false, true]);
    }

    #[test]
    fn sensitivity_ownership_parts_and_legacy_pair() {
        let mut header = Header::from(("key", "value"));
        header.set_sensitive(true);
        let pair: (Bytes, Bytes) = header.clone().into_inner();
        assert_eq!(
            pair,
            (Bytes::from_static(b"key"), Bytes::from_static(b"value"))
        );
        let (key, value, sensitive) = header.into_parts();
        assert!(sensitive);
        let mut restored = Header::new(key, value);
        restored.set_sensitive(sensitive);
        assert!(restored.is_sensitive());
        assert_eq!(restored.into_parts(), (pair.0, pair.1, true));
        assert!(!Header::from(("key", "value")).into_parts().2);
    }

    // from
    #[test]
    fn test_two_header_from_tuple_mixed() {
        let value = "application/json";
        let header: Header = (CONTENT_TYPE, value.as_bytes()).into();
        let expected = Header {
            key: Bytes::from(CT),
            value: Bytes::from(value.to_owned()),
            is_removed: false,
            is_sensitive: false,
        };
        assert_eq!(header, expected);
    }

    #[test]
    fn test_two_header_from_tuple_slice() {
        let key = "Content-Type";
        let value = "application/json";
        let header: Header = (key.as_bytes(), value.as_bytes()).into();
        let expected = Header {
            key: Bytes::from(CT),
            value: Bytes::from(value.to_owned()),
            is_removed: false,
            is_sensitive: false,
        };
        assert_eq!(header, expected);
    }

    #[test]
    fn test_two_header_from_tuple() {
        let key = "Content-Type";
        let value = "application/json";
        let header: Header = (key, value).into();
        let expected = Header {
            key: Bytes::from(CT),
            value: Bytes::from(value.to_owned()),
            is_removed: false,
            is_sensitive: false,
        };
        assert_eq!(header, expected);
    }

    #[test]
    fn test_two_header_from_str() {
        let input = "Content-Type: application/json\r\n";
        let header: Header = (input).into();
        let expected = Header {
            key: Bytes::from(CT),
            value: Bytes::from("application/json".to_owned()),
            is_removed: false,
            is_sensitive: false,
        };
        assert_eq!(header, expected);
    }

    #[test]
    fn test_two_header_from_str_key_only() {
        let input = "Content-Type:";
        let header: Header = (input).into();
        let expected = Header {
            key: Bytes::from(CT),
            value: Bytes::from("".to_owned()),
            is_removed: false,
            is_sensitive: false,
        };
        assert_eq!(header, expected);
    }

    #[test]
    fn test_two_header_from_str_key_only_no_colon() {
        let input = "Content-Type";
        let header: Header = (input).into();
        let expected = Header {
            key: Bytes::from(CT),
            value: Bytes::from("".to_owned()),
            is_removed: false,
            is_sensitive: false,
        };
        assert_eq!(header, expected);
    }

    #[test]
    fn test_two_header_as_ref() {
        let two = Header::from(("key", "value"));
        assert_eq!(two.key_as_ref(), b"key");
        assert_eq!(two.value_as_ref(), b"value");
    }

    #[test]
    fn test_two_header_len() {
        let buf = "content-type: application/json\r\n";
        let header = Header::from(buf);
        assert_eq!(header.len(), 28);
        let buf = "a: b\r\n";
        let header = Header::from(buf);
        assert_eq!(header.len(), 2);
    }

    #[test]
    fn test_two_to_one_perfect() {
        let two = Header::from(("content-type", "application/json"));
        let one = OneHeader::from(two);
        assert_eq!(one.key_as_ref(), b"content-type");
        assert_eq!(one.value_as_ref(), b"application/json");

        let verify = "content-type: application/json\r\n";
        assert_eq!(one.into_bytes(), verify);

        let buf: BytesMut = "content-type: application/json\r\n".into();
        let one = OneHeader::from(buf);
        let two = Header::from(one);
        assert_eq!(two.key_as_ref(), b"content-type");
        assert_eq!(two.value_as_ref(), b"application/json");
    }

    #[test]
    fn test_two_to_one_no_key() {
        let two = Header::from(("", "application/json"));
        let one = OneHeader::from(two);
        assert_eq!(one.key_as_ref(), b"");
        assert_eq!(one.value_as_ref(), b"application/json");
        let verify = ": application/json\r\n";
        assert_eq!(one.into_bytes(), verify);
    }

    #[test]
    fn test_two_to_one_no_value() {
        let two = Header::from(("content-type", ""));
        let one = OneHeader::from(two);
        assert_eq!(one.key_as_ref(), b"content-type");
        assert_eq!(one.value_as_ref(), b"");
        let verify = "content-type: \r\n";
        assert_eq!(one.into_bytes(), verify);
    }

    #[test]
    fn test_truncate_value() {
        let mut input = Header::from(("key", "hola, que, tal"));
        input.truncate_value(9);
        let verify = Header::from(("key", "hola, que"));
        assert_eq!(input, verify);
    }
}
