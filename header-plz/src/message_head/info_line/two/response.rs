use crate::status::StatusCode;

#[derive(Clone, Debug)]
pub struct ResponseLine {
    status: StatusCode,
    is_sensitive: bool,
}

// Encoding policy does not change semantic equality.
impl PartialEq for ResponseLine {
    fn eq(&self, other: &Self) -> bool {
        self.status == other.status
    }
}

impl Default for ResponseLine {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            is_sensitive: false,
        }
    }
}

impl ResponseLine {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            is_sensitive: false,
        }
    }

    /// Returns the status, discarding sensitivity metadata.
    pub fn into_parts(self) -> StatusCode {
        self.status
    }

    /// Returns the status and its never-indexed encoding policy.
    pub fn into_parts_with_sensitivity(self) -> (StatusCode, bool) {
        (self.status, self.is_sensitive)
    }

    /// Whether `:status` must use a never-indexed HPACK representation.
    pub fn is_sensitive(&self) -> bool {
        self.is_sensitive
    }

    /// Sets `:status` policy. Status mutations preserve this flag.
    pub fn set_sensitive(&mut self, sensitive: bool) {
        self.is_sensitive = sensitive;
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status
    }

    pub fn status(&self) -> &StatusCode {
        &self.status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitivity_defaults_clone_equality_and_mutation() {
        let plain = ResponseLine::default();
        assert!(!plain.is_sensitive());
        assert!(!ResponseLine::new(StatusCode::OK).is_sensitive());
        let mut marked = plain.clone();
        marked.set_sensitive(true);
        assert!(marked.clone().is_sensitive());
        assert_eq!(marked, plain);
        marked.set_status(StatusCode::NO_CONTENT);
        assert!(marked.is_sensitive());
        assert_ne!(marked, plain);
        marked.set_sensitive(false);
        assert!(!marked.is_sensitive());
    }

    #[test]
    fn sensitivity_owned_parts_and_legacy_compatibility() {
        let mut original = ResponseLine::new(StatusCode::NO_CONTENT);
        original.set_sensitive(true);
        let legacy: StatusCode = original.clone().into_parts();
        let legacy_rebuilt = ResponseLine::new(legacy);
        assert_eq!(legacy_rebuilt, original);
        assert!(!legacy_rebuilt.is_sensitive());
        let (status, sensitive) =
            original.clone().into_parts_with_sensitivity();
        let mut rebuilt = ResponseLine::new(status);
        rebuilt.set_sensitive(sensitive);
        assert_eq!(rebuilt, original);
        assert!(rebuilt.is_sensitive());
    }
}
