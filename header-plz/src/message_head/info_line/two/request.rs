use bytes::Bytes;

use crate::{
    bytes_str::BytesStr,
    method::Method,
    uri::{InvalidUri, Uri, path::PathAndQuery, scheme::Scheme},
};

/// A request pseudoheader whose HPACK encoding policy can be marked independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestPseudoHeader {
    Method,
    Scheme,
    Authority,
    Path,
    Protocol,
}

impl RequestPseudoHeader {
    fn mask(self) -> u8 {
        match self {
            Self::Method => 1,
            Self::Scheme => 2,
            Self::Authority => 4,
            Self::Path => 8,
            Self::Protocol => 16,
        }
    }
}

/// Per-pseudoheader never-indexed policy, without field values or presence.
/// All flags default to false.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestSensitivity(u8);

impl RequestSensitivity {
    pub fn is_sensitive(self, header: RequestPseudoHeader) -> bool {
        self.0 & header.mask() != 0
    }

    pub fn set_sensitive(
        &mut self,
        header: RequestPseudoHeader,
        sensitive: bool,
    ) {
        if sensitive {
            self.0 |= header.mask();
        } else {
            self.0 &= !header.mask();
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RequestLine {
    method: Method,
    uri: Uri,
    extension: Option<Box<Bytes>>,
    sensitivity: RequestSensitivity,
}

// Encoding policy does not change semantic equality.
impl PartialEq for RequestLine {
    fn eq(&self, other: &Self) -> bool {
        self.method == other.method
            && self.uri == other.uri
            && self.extension == other.extension
    }
}

impl RequestLine {
    pub fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            ..Default::default()
        }
    }

    /// Returns semantic values, discarding sensitivity metadata.
    pub fn into_parts(self) -> (Method, Uri, Option<Box<Bytes>>) {
        (self.method, self.uri, self.extension)
    }

    /// Returns semantic values and their per-pseudoheader encoding policy.
    pub fn into_parts_with_sensitivity(
        self,
    ) -> (Method, Uri, Option<Box<Bytes>>, RequestSensitivity) {
        (self.method, self.uri, self.extension, self.sensitivity)
    }

    pub fn is_sensitive(&self, header: RequestPseudoHeader) -> bool {
        self.sensitivity.is_sensitive(header)
    }

    /// Marks only this pseudoheader; does not create an absent field value.
    /// Existing value mutations preserve the flags.
    pub fn set_sensitive(
        &mut self,
        header: RequestPseudoHeader,
        sensitive: bool,
    ) {
        self.sensitivity.set_sensitive(header, sensitive);
    }

    pub fn sensitivity(&self) -> RequestSensitivity {
        self.sensitivity
    }

    pub fn set_sensitivity(&mut self, sensitivity: RequestSensitivity) {
        self.sensitivity = sensitivity;
    }

    // getters
    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn extension(&self) -> Option<&Bytes> {
        self.extension.as_deref()
    }

    // setters
    pub fn set_method(&mut self, method: Method) {
        self.method = method
    }

    pub fn set_uri(&mut self, uri: Uri) {
        self.uri = uri
    }

    pub fn try_set_scheme<T>(&mut self, scheme: T) -> Result<(), InvalidUri>
    where
        T: TryInto<Scheme>,
        <T as TryInto<Scheme>>::Error: Into<InvalidUri>,
    {
        self.uri.scheme = scheme.try_into().map_err(Into::into)?;
        Ok(())
    }

    pub fn try_set_path<T>(&mut self, path: T) -> Result<(), InvalidUri>
    where
        T: TryInto<PathAndQuery>,
        <T as TryInto<PathAndQuery>>::Error: Into<InvalidUri>,
    {
        self.uri.path_and_query = path.try_into().map_err(Into::into)?;
        Ok(())
    }

    pub fn try_set_authority<T>(
        &mut self,
        authority: T,
    ) -> Result<(), InvalidUri>
    where
        T: TryInto<BytesStr>,
    {
        self.uri.authority =
            authority.try_into().map_err(|_| InvalidUri::Authority)?;
        Ok(())
    }

    pub fn set_extension(&mut self, ext: Bytes) {
        self.extension = Some(Box::new(ext));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSEUDOHEADERS: [RequestPseudoHeader; 5] = [
        RequestPseudoHeader::Method,
        RequestPseudoHeader::Scheme,
        RequestPseudoHeader::Authority,
        RequestPseudoHeader::Path,
        RequestPseudoHeader::Protocol,
    ];

    #[test]
    fn sensitivity_defaults_and_independent_flags() {
        let plain = RequestLine::default();
        let constructed = RequestLine::new(Method::GET, Uri::default());
        for header in PSEUDOHEADERS {
            assert!(!plain.is_sensitive(header));
            assert!(!constructed.is_sensitive(header));
            let mut marked = plain.clone();
            marked.set_sensitive(header, true);
            assert_eq!(marked, plain);
            assert_eq!(marked.uri(), plain.uri());
            assert_eq!(marked.extension(), None);
            for other in PSEUDOHEADERS {
                assert_eq!(marked.is_sensitive(other), other == header);
            }
            assert!(marked.clone().is_sensitive(header));
            marked.set_sensitive(header, false);
            assert_eq!(marked.sensitivity(), RequestSensitivity::default());
        }
    }

    #[test]
    fn sensitivity_survives_value_mutations() {
        let mut req = RequestLine::default();
        for header in PSEUDOHEADERS {
            req.set_sensitive(header, true);
        }
        let policy = req.sensitivity();
        req.set_method(Method::CONNECT);
        req.set_uri(Uri::builder().path("/test").build().unwrap());
        req.set_extension(Bytes::from_static(b"websocket"));
        req.try_set_scheme("https").unwrap();
        req.try_set_authority("example.com").unwrap();
        req.try_set_path("/other").unwrap();
        assert_eq!(req.sensitivity(), policy);
        assert!(req.try_set_scheme(b"\xff".as_slice()).is_err());
        assert!(req.try_set_path(b"\xff".as_slice()).is_err());
        assert!(req.try_set_authority(b"\xff".as_slice()).is_err());
        assert_eq!(req.sensitivity(), policy);
        assert_ne!(req, RequestLine::default());
    }

    #[test]
    fn sensitivity_owned_parts_and_legacy_compatibility() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com")
            .path("/test")
            .build()
            .unwrap();
        let mut original = RequestLine::new(Method::CONNECT, uri);
        original.set_extension(Bytes::from_static(b"websocket"));
        for header in PSEUDOHEADERS {
            original.set_sensitive(header, true);
        }
        let legacy: (Method, Uri, Option<Box<Bytes>>) =
            original.clone().into_parts();
        let mut legacy_rebuilt = RequestLine::new(legacy.0, legacy.1);
        legacy_rebuilt.set_extension(*legacy.2.unwrap());
        assert_eq!(legacy_rebuilt, original);
        assert_eq!(
            legacy_rebuilt.sensitivity(),
            RequestSensitivity::default()
        );
        let (method, uri, protocol, policy) =
            original.clone().into_parts_with_sensitivity();
        let mut rebuilt = RequestLine::new(method, uri);
        rebuilt.set_extension(*protocol.unwrap());
        rebuilt.set_sensitivity(policy);
        assert_eq!(rebuilt, original);
        for header in PSEUDOHEADERS {
            assert!(rebuilt.is_sensitive(header));
        }
        assert_eq!(rebuilt.sensitivity(), original.sensitivity());
    }

    #[test]
    fn test_request_line_setters() {
        let mut req = RequestLine::default();

        req.set_method(Method::DELETE);
        assert_eq!(*req.method(), Method::DELETE);

        let new_uri = Uri::builder().path("/test").build().unwrap();
        req.set_uri(new_uri.clone());
        assert_eq!(*req.uri(), new_uri);

        let ext = Bytes::from("extension");
        req.set_extension(ext.clone());
        assert_eq!(req.extension(), Some(&ext));

        assert!(req.try_set_scheme("https").is_ok());
        assert_eq!(req.uri().scheme(), Some(&Scheme::HTTPS));

        assert!(req.try_set_authority("example.com").is_ok());
        assert_eq!(req.uri().authority(), Some("example.com"));

        assert!(req.try_set_path("/foo/bar").is_ok());
        assert_eq!(req.uri().path(), "/foo/bar");

        let uri = req.uri();
        assert_eq!(uri.scheme(), Some(&Scheme::HTTPS));
        assert_eq!(uri.authority(), Some("example.com"));
        assert_eq!(uri.path(), "/foo/bar");
    }
}
