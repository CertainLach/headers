use headers_core::HeaderValue;
use util::{Comma, FlatCsv};

/// The `www-authenticate` header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WwwAuthenticate(HeaderValue, FlatCsv<Comma>);

impl crate::Header for WwwAuthenticate {
    fn name() -> &'static ::http::header::HeaderName {
        &::http::header::WWW_AUTHENTICATE
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, ::Error>
    where
        I: Iterator<Item = &'i ::http::header::HeaderValue>,
    {
        values
            .next()
            .and_then(|val| {
                if let Some(ws) = val.as_bytes().iter().position(|c| *c == b' ') {
                    let type_ = HeaderValue::from_bytes(&val.as_bytes()[..ws]).ok()?;
                    let slice = HeaderValue::from_bytes(&val.as_bytes()[ws + 1..]).ok()?;
                    Some(Self(type_, slice.into()))
                } else {
                    Some(Self(val.clone(), FlatCsv::default()))
                }
            })
            .ok_or_else(::Error::invalid)
    }

    fn encode<E: Extend<::HeaderValue>>(&self, values: &mut E) {
        values.extend(vec![self.0.clone(), (&self.1).into()]);
    }
}

impl WwwAuthenticate {
    /// Get auth type
    pub fn scheme(&self) -> Option<&str> {
        self.0.to_str().ok()
    }

    /// Get header value
    pub fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|&(key, _)| key == name)
            .map(|(_, val)| val)
    }

    /// Get the number of key-value pairs this `WwwAuthenticate` contains.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Iterator the key-value pairs of this `WwwAuthenticate` header.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.1.iter().filter_map(|kv| {
            let mut iter = kv.splitn(2, '=');
            let key = iter.next()?.trim();
            let val = iter.next()?.trim();
            let val = if val.starts_with('"') {
                &val[1..val.len() - 1]
            } else {
                val
            };
            Some((key, val))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::WwwAuthenticate;

    #[test]
    fn test_parse() {
        let auth = test_decode::<WwwAuthenticate>(&["Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/redis:pull\""]).unwrap();

        assert_eq!(auth.get("realm"), Some("https://auth.docker.io/token"));
        assert_eq!(auth.get("bar"), None);
    }

    #[test]
    fn test_parse_empty() {
        let auth = test_decode::<WwwAuthenticate>(&["Basic"]).unwrap();

        assert_eq!(auth.scheme(), Some("Basic"));
    }
}
