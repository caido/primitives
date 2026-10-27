use content_encoding::ContentEncoding;
use mime_plz::ContentType;
use transfer_types::TransferType;

use crate::body_headers::encoding_info::EncodingInfo;
pub mod content_encoding;
pub mod encoding_info;
pub mod transfer_types;

mod from_header_map;
pub mod parse;

#[derive(Clone, Eq, Debug, Default, PartialEq)]
pub struct BodyHeader {
    pub content_encoding: Option<Vec<EncodingInfo>>,
    pub content_type: Option<ContentType>,
    pub transfer_encoding: Option<Vec<EncodingInfo>>,
    pub transfer_type: Option<TransferType>,
}

impl BodyHeader {
    pub fn sanitize(self) -> Option<Self> {
        if self.content_encoding.is_some()
            || self.content_type.is_some()
            || self.transfer_encoding.is_some()
            || self.transfer_type.is_some()
        {
            Some(self)
        } else {
            None
        }
    }

    pub fn content_type(&self) -> ContentType {
        self.content_type.unwrap_or(ContentType::Unknown)
    }

    pub fn chunked_te_position(&self) -> Option<(usize, usize)> {
        self.transfer_encoding.as_ref().and_then(|einfo_vec| {
            einfo_vec.iter().enumerate().find_map(|(outer_idx, ei)| {
                ei.encodings()
                    .iter()
                    .position(|enc| *enc == ContentEncoding::Chunked)
                    .map(|inner_idx| (outer_idx, inner_idx))
            })
        })
    }

    pub fn update_transfer_type(&mut self, transfer_type: TransferType) {
        if self.transfer_type.is_none_or(|tt| transfer_type >= tt) {
            self.transfer_type = Some(transfer_type);
        }
    }

    fn has_single_te_encoding(&self, encoding: &ContentEncoding) -> bool {
        self.transfer_encoding.as_ref().is_some_and(|einfo_vec| {
            einfo_vec.len() == 1
                && einfo_vec[0].encodings().len() == 1
                && &einfo_vec[0].encodings()[0] == encoding
        })
    }

    pub fn is_chunked_te_only(&self) -> bool {
        self.has_single_te_encoding(&ContentEncoding::Chunked)
    }

    pub fn is_identity_te_only(&self) -> bool {
        self.has_single_te_encoding(&ContentEncoding::Identity)
    }

    pub fn is_identity_ce_only(&self) -> bool {
        self.content_encoding.as_ref().is_some_and(|einfo_vec| {
            einfo_vec.len() == 1
                && einfo_vec[0].encodings().len() == 1
                && einfo_vec[0].encodings()[0] == ContentEncoding::Identity
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // sanitize
    #[test]
    fn test_bodyheader_sanitize_all() {
        let body = BodyHeader {
            content_encoding: Some(vec![EncodingInfo::new(
                0,
                vec![ContentEncoding::Gzip],
            )]),
            content_type: Some(ContentType::Application),
            transfer_encoding: Some(vec![EncodingInfo::new(
                0,
                vec![ContentEncoding::Gzip],
            )]),
            transfer_type: Some(TransferType::Close),
        };
        let sbody = body.clone().sanitize();
        assert_eq!(sbody.unwrap(), body);
    }

    #[test]
    fn test_bodyheader_sanitize_none() {
        let body = BodyHeader::default();
        assert!(body.sanitize().is_none());
    }

    // content type
    #[test]
    fn test_bodyheader_content_type() {
        let body = BodyHeader {
            content_type: Some(ContentType::Application),
            ..Default::default()
        };
        assert_eq!(body.content_type(), ContentType::Application);
    }

    #[test]
    fn test_bodyheader_content_type_default() {
        let body = BodyHeader::default();
        assert_eq!(body.content_type(), ContentType::Unknown);
    }

    // chunked te position
    #[test]
    fn test_bodyheader_chunked_te_position_none() {
        let body = BodyHeader::default();
        assert_eq!(body.chunked_te_position(), None);
    }

    #[test]
    fn test_bodyheader_chunked_te_position_single() {
        let body = BodyHeader {
            transfer_encoding: Some(vec![EncodingInfo::new(
                0,
                vec![ContentEncoding::Chunked],
            )]),
            ..Default::default()
        };
        assert_eq!(body.chunked_te_position(), Some((0, 0)));
    }

    #[test]
    fn test_bodyheader_chunked_te_position_multi() {
        let body = BodyHeader {
            transfer_encoding: Some(vec![
                EncodingInfo::new(0, vec![ContentEncoding::Brotli]),
                EncodingInfo::new(1, vec![ContentEncoding::Identity]),
                EncodingInfo::new(1, vec![ContentEncoding::Gzip]),
                EncodingInfo::new(1, vec![ContentEncoding::Chunked]),
            ]),
            ..Default::default()
        };
        assert_eq!(body.chunked_te_position(), Some((3, 0)));
    }

    // is_chunked_te_only
    #[test]
    fn test_bodyheader_is_chunked_te_only_true() {
        let body = BodyHeader {
            transfer_encoding: Some(vec![EncodingInfo::new(
                0,
                vec![ContentEncoding::Chunked],
            )]),
            ..Default::default()
        };
        assert!(body.is_chunked_te_only());
    }

    #[test]
    fn test_bodyheader_is_chunked_te_only_none_false() {
        let body = BodyHeader::default();
        assert!(!body.is_chunked_te_only());
    }

    #[test]
    fn test_bodyheader_is_chunked_te_only_multi_false() {
        let body = BodyHeader {
            transfer_encoding: Some(vec![
                EncodingInfo::new(0, vec![ContentEncoding::Brotli]),
                EncodingInfo::new(1, vec![ContentEncoding::Identity]),
                EncodingInfo::new(1, vec![ContentEncoding::Gzip]),
                EncodingInfo::new(1, vec![ContentEncoding::Chunked]),
            ]),
            ..Default::default()
        };
        assert!(!body.is_chunked_te_only());
    }

    // is_identity_te_only
    #[test]
    fn test_bodyheader_is_identity_te_only_true() {
        let body = BodyHeader {
            transfer_encoding: Some(vec![EncodingInfo::new(
                0,
                vec![ContentEncoding::Identity],
            )]),
            ..Default::default()
        };
        assert!(body.is_identity_te_only());
    }

    #[test]
    fn test_bodyheader_is_identity_te_only_none_false() {
        let body = BodyHeader::default();
        assert!(!body.is_identity_te_only());
    }

    #[test]
    fn test_bodyheader_is_identity_te_only_multi_false() {
        let body = BodyHeader {
            transfer_encoding: Some(vec![
                EncodingInfo::new(0, vec![ContentEncoding::Brotli]),
                EncodingInfo::new(1, vec![ContentEncoding::Identity]),
                EncodingInfo::new(1, vec![ContentEncoding::Gzip]),
                EncodingInfo::new(1, vec![ContentEncoding::Chunked]),
            ]),
            ..Default::default()
        };
        assert!(!body.is_identity_te_only());
    }

    // is_identity_ce_only
    #[test]
    fn test_bodyheader_is_identity_ce_only_true() {
        let body = BodyHeader {
            content_encoding: Some(vec![EncodingInfo::new(
                0,
                vec![ContentEncoding::Identity],
            )]),
            ..Default::default()
        };
        assert!(body.is_identity_ce_only());
    }

    #[test]
    fn test_bodyheader_is_identity_ce_only_none_false() {
        let body = BodyHeader::default();
        assert!(!body.is_identity_ce_only());
    }

    #[test]
    fn test_bodyheader_is_identity_ce_only_multi_false() {
        let body = BodyHeader {
            content_encoding: Some(vec![
                EncodingInfo::new(0, vec![ContentEncoding::Brotli]),
                EncodingInfo::new(1, vec![ContentEncoding::Identity]),
                EncodingInfo::new(1, vec![ContentEncoding::Gzip]),
                EncodingInfo::new(1, vec![ContentEncoding::Chunked]),
            ]),
            ..Default::default()
        };
        assert!(!body.is_identity_ce_only());
    }
}
