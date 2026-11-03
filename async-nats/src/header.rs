// Copyright 2020-2023 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// NOTE(thomastaylor312): This clippy lint is coming from serialize and deserialize and is likely a
// false positive due to the bytes crate, see
// https://rust-lang.github.io/rust-clippy/master/index.html#/mutable_key_type for more details.
// Sorry to make this global to this module, rather than on the `HeaderMap` struct, but because it
// is coming from the derive, it didn't work to set it on the struct.
#![allow(clippy::mutable_key_type)]

//! NATS [Message][crate::Message] headers, modeled loosely after the `http::header` crate.

use std::{
    collections::HashMap,
    fmt,
    slice::Iter,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A struct for handling NATS headers.
/// Has a similar API to `http::header`, but properly serializes and deserializes
/// according to NATS requirements.
///
/// # Examples
///
/// ```
/// # #[tokio::main]
/// # async fn main() -> Result<(), async_nats::Error> {
/// let client = async_nats::connect("demo.nats.io").await?;
/// let mut headers = async_nats::HeaderMap::new();
/// headers.insert("Key", "Value");
/// client
///     .publish_with_headers("subject", headers, "payload".into())
///     .await?;
/// # Ok(())
/// # }
/// ```

#[derive(Clone, Debug, Default)]
pub struct HeaderMap {
    inner: HeaderStorage,
}

#[derive(Clone, Debug)]
enum HeaderStorage {
    Indexed(HashMap<HeaderName, Vec<HeaderValue>>),
    Projection(Arc<HeaderProjection>),
}

impl Default for HeaderStorage {
    fn default() -> Self {
        Self::Indexed(HashMap::new())
    }
}

#[derive(Debug)]
enum TransportHeaders {
    Received(ReceivedHeaders),
    Ordered(OrderedHeaders),
}

#[derive(Debug)]
struct ReceivedHeaders {
    text: HeaderText,
    pairs: smallvec::SmallVec<[HeaderIndex; 1]>,
}

#[derive(Debug)]
struct HeaderIndex {
    name_start: u32,
    name_end: u32,
    value_start: u32,
    value_end: u32,
}

#[derive(Debug)]
struct OrderedHeaders {
    pairs: Vec<(String, String)>,
    message_id: Option<HeaderValue>,
    expected_stream: Option<HeaderValue>,
}

#[derive(Debug)]
struct HeaderProjection {
    data: TransportHeaders,
    indexed: OnceLock<HashMap<HeaderName, Vec<HeaderValue>>>,
}

impl PartialEq for HeaderMap {
    fn eq(&self, other: &Self) -> bool {
        self.indexed() == other.indexed()
    }
}

impl Eq for HeaderMap {}

impl HeaderMap {
    fn indexed(&self) -> &HashMap<HeaderName, Vec<HeaderValue>> {
        let cache = match &self.inner {
            HeaderStorage::Indexed(values) => return values,
            HeaderStorage::Projection(projection) => &projection.indexed,
        };
        cache.get_or_init(|| {
            let mut values = HashMap::<HeaderName, Vec<HeaderValue>>::new();
            for (name, value) in self.iter_ordered() {
                values
                    .entry(HeaderName::from_str(name).expect("validated header name"))
                    .or_default()
                    .push(HeaderValue::from(value));
            }
            values
        })
    }

    fn indexed_mut(&mut self) -> &mut HashMap<HeaderName, Vec<HeaderValue>> {
        if !matches!(&self.inner, HeaderStorage::Indexed(_)) {
            self.inner = HeaderStorage::Indexed(self.indexed().clone());
        }
        match &mut self.inner {
            HeaderStorage::Indexed(values) => values,
            HeaderStorage::Projection(_) => unreachable!(),
        }
    }

    /// Take ownership of already ordered transport pairs. No names, values or encoded bytes
    /// are copied, so payload-size validation still precedes wire-buffer allocation.
    pub fn from_ordered(pairs: Vec<(String, String)>) -> Self {
        if pairs.is_empty() {
            return Self::new();
        }
        for (name, value) in &pairs {
            assert!(validate_header_name(name).is_ok(), "invalid header name");
            assert!(validate_header_value(value).is_ok(), "invalid header value");
        }
        Self {
            inner: HeaderStorage::Projection(Arc::new(HeaderProjection {
                data: TransportHeaders::Ordered(OrderedHeaders {
                    pairs,
                    message_id: None,
                    expected_stream: None,
                }),
                indexed: OnceLock::new(),
            })),
        }
    }

    /// Stream publication keeps its reserved overrides outside the owned ordered vector,
    /// avoiding a vector growth or copying the caller's names and values before size admission.
    pub fn from_ordered_with_stream(
        mut pairs: Vec<(String, String)>,
        message_id: Option<String>,
        stream: String,
    ) -> Self {
        pairs.retain(|(name, _)| {
            name != NATS_EXPECTED_STREAM.as_str()
                && (message_id.is_none() || name != NATS_MESSAGE_ID.as_str())
        });
        if pairs.is_empty() {
            let mut headers = Self::new();
            if let Some(id) = message_id {
                headers.insert(NATS_MESSAGE_ID, id);
            }
            headers.insert(NATS_EXPECTED_STREAM, stream);
            return headers;
        }
        let mut headers = Self::from_ordered(pairs);
        let HeaderStorage::Projection(ordered) = &mut headers.inner else {
            unreachable!()
        };
        let TransportHeaders::Ordered(data) = &mut Arc::get_mut(ordered)
            .expect("new projection is exclusively owned")
            .data
        else {
            unreachable!()
        };
        data.message_id = message_id.map(HeaderValue::from);
        data.expected_stream = Some(HeaderValue::from(stream));
        headers
    }

    /// Validate and index the received block without copying names or values. A NATS server's
    /// signed 32-bit payload bound fits these offsets. The conversion remains checked for peers
    /// that violate that transport contract. Continuations are folded in the existing frame.
    pub(crate) fn from_received(mut block: BytesMut) -> std::io::Result<Self> {
        fn offset(value: usize) -> std::io::Result<u32> {
            u32::try_from(value)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
        }
        let text = std::str::from_utf8(&block)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let origin = text.as_ptr() as usize;
        let mut lines = text.lines().skip(1).peekable();
        let mut pairs = smallvec::SmallVec::<[HeaderIndex; 1]>::new();
        while let Some(line) = lines.next() {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "no header version line found",
                )
            })?;
            validate_header_name(name)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            let name_start = name.as_ptr() as usize - origin;
            let value = value.trim_start();
            let value_start = value.as_ptr() as usize - origin;
            let mut raw_end = value_start + value.len();
            while let Some(continuation) =
                lines.next_if(|line| line.starts_with(char::is_whitespace))
            {
                raw_end = continuation.as_ptr() as usize - origin + continuation.len();
            }
            let value_end = value_start + text[value_start..raw_end].trim_end().len();
            pairs.push(HeaderIndex {
                name_start: offset(name_start)?,
                name_end: offset(name_start + name.len())?,
                value_start: offset(value_start)?,
                value_end: offset(value_end)?,
            });
        }
        if pairs.is_empty() {
            return Ok(Self::new());
        }
        for pair in &mut pairs {
            let start = pair.value_start as usize;
            let end = pair.value_end as usize;
            let mut read = start;
            let mut written = start;
            while read < end {
                let newline = memchr::memchr(b'\n', &block[read..end]).map(|offset| read + offset);
                let next = newline.unwrap_or(end);
                let content_end = if newline.is_some() && next > read && block[next - 1] == b'\r' {
                    next - 1
                } else {
                    next
                };
                if memchr::memchr(b'\r', &block[read..content_end]).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        ParseHeaderValueError,
                    ));
                }
                if written != read {
                    block.copy_within(read..content_end, written);
                }
                written += content_end - read;
                read = newline.map_or(end, |position| position + 1);
            }
            // Both the copied prefix and untouched suffix end at UTF-8 boundaries. Erase the
            // abandoned continuation bytes so the complete immutable block also stays UTF-8.
            if written < end {
                block[written..end].fill(b' ');
            }
            pair.value_end = offset(written)?;
        }
        Ok(Self {
            inner: HeaderStorage::Projection(Arc::new(HeaderProjection {
                data: TransportHeaders::Received(ReceivedHeaders {
                    text: HeaderText {
                        bytes: block.freeze(),
                    },
                    pairs,
                }),
                indexed: OnceLock::new(),
            })),
        })
    }

    /// Borrow the first value without constructing the indexed SDK projection.
    pub fn get_str(&self, name: &'static str) -> Option<&str> {
        match &self.inner {
            HeaderStorage::Indexed(values) => values
                .get(&HeaderName::from_static(name))?
                .first()
                .map(HeaderValue::as_str),
            HeaderStorage::Projection(_) => self
                .iter_ordered()
                .find_map(|(key, value)| (key == name).then_some(value)),
        }
    }

    /// Borrow every pair in its transport position. Indexed authoring maps group their values.
    pub fn iter_ordered(&self) -> HeaderPairs<'_> {
        HeaderPairs {
            inner: match &self.inner {
                HeaderStorage::Indexed(values) => HeaderPairsInner::Indexed {
                    entries: values.iter(),
                    values: None,
                },
                HeaderStorage::Projection(projection) => match &projection.data {
                    TransportHeaders::Received(block) => HeaderPairsInner::Block {
                        text: block.text.as_str(),
                        pairs: block.pairs.iter(),
                    },
                    TransportHeaders::Ordered(pairs) => HeaderPairsInner::Ordered {
                        pairs: pairs.pairs.iter(),
                        message_id: pairs.message_id.as_ref(),
                        expected_stream: pairs.expected_stream.as_ref(),
                    },
                },
            },
        }
    }
}

/// Borrowed header pairs; constructing or walking it allocates no storage.
pub struct HeaderPairs<'a> {
    inner: HeaderPairsInner<'a>,
}

enum HeaderPairsInner<'a> {
    Indexed {
        entries: std::collections::hash_map::Iter<'a, HeaderName, Vec<HeaderValue>>,
        values: Option<(&'a HeaderName, std::slice::Iter<'a, HeaderValue>)>,
    },
    Block {
        text: &'a str,
        pairs: std::slice::Iter<'a, HeaderIndex>,
    },
    Ordered {
        pairs: std::slice::Iter<'a, (String, String)>,
        message_id: Option<&'a HeaderValue>,
        expected_stream: Option<&'a HeaderValue>,
    },
}

impl<'a> Iterator for HeaderPairs<'a> {
    type Item = (&'a str, &'a str);
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            HeaderPairsInner::Indexed { entries, values } => loop {
                if let Some((name, current)) = values {
                    if let Some(value) = current.next() {
                        return Some((name.as_str(), value.as_str()));
                    }
                }
                let (name, current) = entries.next()?;
                *values = Some((name, current.iter()));
            },
            HeaderPairsInner::Block { text, pairs } => pairs.next().map(|pair| {
                (
                    &text[pair.name_start as usize..pair.name_end as usize],
                    &text[pair.value_start as usize..pair.value_end as usize],
                )
            }),
            HeaderPairsInner::Ordered {
                pairs,
                message_id,
                expected_stream,
            } => pairs
                .next()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .or_else(|| {
                    message_id
                        .take()
                        .map(|value| (NATS_MESSAGE_ID.as_str(), value.as_str()))
                })
                .or_else(|| {
                    expected_stream
                        .take()
                        .map(|value| (NATS_EXPECTED_STREAM.as_str(), value.as_str()))
                }),
        }
    }
}

/// Helper enum for backward-compatible deserialization using serde's untagged feature
/// This is required because of the bug #1470 where the client incorrectly serialized
/// headers with an "inner" wrapper.
#[derive(Deserialize)]
#[serde(untagged)]
enum HeaderMapHelper {
    // Legacy format with "inner" wrapper
    Legacy {
        inner: HashMap<HeaderName, Vec<HeaderValue>>,
    },
    // Proper format - direct HashMap
    Current(HashMap<HeaderName, Vec<HeaderValue>>),
}

impl<'de> Deserialize<'de> for HeaderMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Use the untagged enum to automatically try both formats
        let helper = HeaderMapHelper::deserialize(deserializer)?;

        Ok(match helper {
            HeaderMapHelper::Legacy { inner } => HeaderMap {
                inner: HeaderStorage::Indexed(inner),
            },
            HeaderMapHelper::Current(inner) => HeaderMap {
                inner: HeaderStorage::Indexed(inner),
            },
        })
    }
}

impl Serialize for HeaderMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as the new format (direct HashMap without "inner" wrapper)
        self.indexed().serialize(serializer)
    }
}

impl FromIterator<(HeaderName, HeaderValue)> for HeaderMap {
    fn from_iter<T: IntoIterator<Item = (HeaderName, HeaderValue)>>(iter: T) -> Self {
        let mut header_map = HeaderMap::new();
        for (key, value) in iter {
            header_map.insert(key, value);
        }
        header_map
    }
}

impl HeaderMap {
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, HeaderName, Vec<HeaderValue>> {
        self.indexed().iter()
    }
}

pub struct GetAll<'a, T> {
    inner: Iter<'a, T>,
}

impl<'a, T> Iterator for GetAll<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}
impl<T> ExactSizeIterator for GetAll<'_, T> {}

impl HeaderMap {
    /// Create an empty `HeaderMap`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_nats::HeaderMap;
    /// let map = HeaderMap::new();
    ///
    /// assert!(map.is_empty());
    /// ```
    pub fn new() -> Self {
        HeaderMap::default()
    }

    /// Returns true if the map contains no elements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_nats::HeaderMap;
    /// # use async_nats::header::NATS_SUBJECT;
    /// let mut map = HeaderMap::new();
    ///
    /// assert!(map.is_empty());
    ///
    /// map.insert(NATS_SUBJECT, "FOO.BAR");
    ///
    /// assert!(!map.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            HeaderStorage::Indexed(values) => values.is_empty(),
            HeaderStorage::Projection(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        self.indexed().len()
    }

    /// Serialized byte length of this header block (as [`HeaderMap::to_bytes`]
    /// produces), computed without allocating.
    pub(crate) fn wire_len(&self) -> usize {
        b"NATS/1.0\r\n\r\n".len()
            + self
                .iter_ordered()
                .map(|(name, value)| name.len() + value.len() + 4)
                .sum::<usize>()
    }
}

impl HeaderMap {
    /// Inserts a new value to a [HeaderMap].
    ///
    /// # Examples
    ///
    /// ```
    /// use async_nats::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("Key", "Value");
    /// ```
    pub fn insert<K: IntoHeaderName, V: IntoHeaderValue>(&mut self, name: K, value: V) {
        let name = name.into_header_name();
        let value = value.into_header_value();
        self.indexed_mut().insert(name, vec![value]);
    }

    /// Appends a new value to the list of values to a given key.
    /// If the key did not exist, it will be inserted with provided value.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_nats::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.append("Key", "Value");
    /// headers.append("Key", "Another");
    pub fn append<K: IntoHeaderName, V: IntoHeaderValue>(&mut self, name: K, value: V) {
        let key = name.into_header_name();
        let value = value.into_header_value();
        let v = self.indexed_mut().get_mut(&key);
        match v {
            Some(v) => {
                v.push(value);
            }
            None => {
                self.insert(key, value);
            }
        }
    }

    /// Gets a value for a given key. If key is not found, [Option::None] is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_nats::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.append("Key", "Value");
    /// let values = headers.get("Key").unwrap();
    /// ```
    pub fn get<K: IntoHeaderName>(&self, key: K) -> Option<&HeaderValue> {
        self.indexed()
            .get(&key.into_header_name())
            .and_then(|x| x.first())
    }

    /// Gets a last value for a given key. If key is not found, [Option::None] is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_nats::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.append("Key", "Value");
    /// let values = headers.get_last("Key").unwrap();
    /// ```
    pub fn get_last<K: IntoHeaderName>(&self, key: K) -> Option<&HeaderValue> {
        self.indexed()
            .get(&key.into_header_name())
            .and_then(|x| x.last())
    }

    /// Gets an iterator to the values for a given key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_nats::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.append("Key", "Value1");
    /// headers.append("Key", "Value2");
    /// let mut values = headers.get_all("Key");
    /// let value1 = values.next();
    /// let value2 = values.next();
    /// ```
    pub fn get_all<K: IntoHeaderName>(&self, key: K) -> GetAll<'_, HeaderValue> {
        let inner = self
            .indexed()
            .get(&key.into_header_name())
            .map(|x| x.iter())
            .unwrap_or([].iter());

        GetAll { inner }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = match &self.inner {
            HeaderStorage::Indexed(_) => Vec::new(),
            HeaderStorage::Projection(_) => Vec::with_capacity(self.wire_len()),
        };
        buf.extend_from_slice(b"NATS/1.0\r\n");
        for (name, value) in self.iter_ordered() {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

/// Represents NATS header field value.
///
/// # Examples
///
/// ```
/// # use async_nats::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("Key", "Value");
/// headers.insert("Another", "AnotherValue");
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HeaderValue {
    inner: String,
}

impl fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_str(), f)
    }
}

impl AsRef<[u8]> for HeaderValue {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl AsRef<str> for HeaderValue {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<i16> for HeaderValue {
    fn from(v: i16) -> Self {
        Self {
            inner: v.to_string(),
        }
    }
}

impl From<i32> for HeaderValue {
    fn from(v: i32) -> Self {
        Self {
            inner: v.to_string(),
        }
    }
}

impl From<i64> for HeaderValue {
    fn from(v: i64) -> Self {
        Self {
            inner: v.to_string(),
        }
    }
}

impl From<isize> for HeaderValue {
    fn from(v: isize) -> Self {
        Self {
            inner: v.to_string(),
        }
    }
}

impl From<u16> for HeaderValue {
    fn from(v: u16) -> Self {
        Self {
            inner: v.to_string(),
        }
    }
}

impl From<u32> for HeaderValue {
    fn from(v: u32) -> Self {
        Self {
            inner: v.to_string(),
        }
    }
}

impl From<u64> for HeaderValue {
    fn from(v: u64) -> Self {
        Self {
            inner: v.to_string(),
        }
    }
}

impl From<usize> for HeaderValue {
    fn from(v: usize) -> Self {
        Self {
            inner: v.to_string(),
        }
    }
}

impl FromStr for HeaderValue {
    type Err = ParseHeaderValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_header_value(s)?;
        Ok(HeaderValue {
            inner: s.to_string(),
        })
    }
}

impl From<&str> for HeaderValue {
    fn from(v: &str) -> Self {
        assert!(
            validate_header_value(v).is_ok(),
            "invalid header value: cannot contain '\\r' or '\\n'"
        );
        Self {
            inner: v.to_string(),
        }
    }
}

impl From<String> for HeaderValue {
    fn from(inner: String) -> Self {
        assert!(
            validate_header_value(&inner).is_ok(),
            "invalid header value: cannot contain '\\r' or '\\n'"
        );
        Self { inner }
    }
}

impl HeaderValue {
    pub fn new() -> Self {
        HeaderValue::default()
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }
}

#[derive(Debug, Clone)]
pub struct ParseHeaderValueError;

impl fmt::Display for ParseHeaderValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"invalid character found in header value (value cannot contain '\r' or '\n')"#
        )
    }
}

impl std::error::Error for ParseHeaderValueError {}

fn validate_header_value(s: &str) -> Result<(), ParseHeaderValueError> {
    if s.contains(['\r', '\n']) {
        Err(ParseHeaderValueError)
    } else {
        Ok(())
    }
}

pub trait IntoHeaderName {
    fn into_header_name(self) -> HeaderName;
}

impl IntoHeaderName for &str {
    fn into_header_name(self) -> HeaderName {
        assert!(
            validate_header_name(self).is_ok(),
            "invalid header name: cannot contain control characters, non-ASCII, or ':'"
        );
        match StandardHeader::from_bytes(self.as_bytes()) {
            Some(v) => HeaderName {
                inner: HeaderRepr::Standard(v),
            },
            None => HeaderName {
                inner: HeaderRepr::Custom(self.into()),
            },
        }
    }
}

impl IntoHeaderName for String {
    fn into_header_name(self) -> HeaderName {
        assert!(
            validate_header_name(&self).is_ok(),
            "invalid header name: cannot contain control characters, non-ASCII, or ':'"
        );
        match StandardHeader::from_bytes(self.as_bytes()) {
            Some(v) => HeaderName {
                inner: HeaderRepr::Standard(v),
            },
            None => HeaderName {
                inner: HeaderRepr::Custom(self.into()),
            },
        }
    }
}

impl IntoHeaderName for HeaderName {
    fn into_header_name(self) -> HeaderName {
        self
    }
}

pub trait IntoHeaderValue {
    fn into_header_value(self) -> HeaderValue;
}

impl IntoHeaderValue for &str {
    fn into_header_value(self) -> HeaderValue {
        HeaderValue::from(self)
    }
}

impl IntoHeaderValue for String {
    fn into_header_value(self) -> HeaderValue {
        HeaderValue::from(self)
    }
}

impl IntoHeaderValue for HeaderValue {
    fn into_header_value(self) -> HeaderValue {
        self
    }
}

macro_rules! standard_headers {
    (
        $(
            $(#[$docs:meta])*
            ($variant:ident, $constant:ident, $bytes:literal);
        )+
    ) => {
        #[allow(clippy::enum_variant_names)]
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
        enum StandardHeader {
            $(
                $variant,
            )+
        }

        $(
            $(#[$docs])*
            pub const $constant: HeaderName = HeaderName {
                inner: HeaderRepr::Standard(StandardHeader::$variant),
            };
        )+

        impl StandardHeader {
            #[inline]
            fn as_str(&self) -> &'static str {
                match *self {
                    $(
                    StandardHeader::$variant => unsafe { std::str::from_utf8_unchecked( $bytes ) },
                    )+
                }
            }

            const fn from_bytes(bytes: &[u8]) -> Option<StandardHeader> {
                match bytes {
                    $(
                        $bytes => Some(StandardHeader::$variant),
                    )+
                    _ => None,
                }
            }
        }

        #[cfg(test)]
        mod standard_header_tests {
            use super::HeaderName;
            use std::str::{self, FromStr};

            const TEST_HEADERS: &'static [(&'static HeaderName, &'static [u8])] = &[
                $(
                (&super::$constant, $bytes),
                )+
            ];

            #[test]
            fn from_str() {
                for &(header, bytes) in TEST_HEADERS {
                    let utf8 = str::from_utf8(bytes).expect("string constants isn't utf8");
                    assert_eq!(HeaderName::from_str(utf8).unwrap(), *header);
                }
            }
        }
    }
}

// Generate constants for all standard NATS headers.
standard_headers! {
    /// The name of the stream the message belongs to.
    (NatsStream, NATS_STREAM, b"Nats-Stream");
    /// The sequence number of the message within the stream.
    (NatsSequence, NATS_SEQUENCE, b"Nats-Sequence");
    /// The timestamp of when the message was sent.
    (NatsTimeStamp, NATS_TIME_STAMP, b"Nats-Time-Stamp");
    /// The subject of the message, used for routing and filtering messages.
    (NatsSubject, NATS_SUBJECT, b"Nats-Subject");
    /// A unique identifier for the message.
    (NatsMessageId, NATS_MESSAGE_ID, b"Nats-Msg-Id");
    /// The last known stream the message was part of.
    (NatsLastStream, NATS_LAST_STREAM, b"Nats-Last-Stream");
    /// The last known consumer that processed the message.
    (NatsLastConsumer, NATS_LAST_CONSUMER, b"Nats-Last-Consumer");
    /// The last known sequence number of the message.
    (NatsLastSequence, NATS_LAST_SEQUENCE, b"Nats-Last-Sequence");
    /// The expected last sequence number of the subject.
    (NatsExpectedLastSubjectSequence, NATS_EXPECTED_LAST_SUBJECT_SEQUENCE, b"Nats-Expected-Last-Subject-Sequence");
    /// The expected last message ID within the stream.
    (NatsExpectedLastMessageId, NATS_EXPECTED_LAST_MESSAGE_ID, b"Nats-Expected-Last-Msg-Id");
    /// The expected last sequence number within the stream.
    (NatsExpectedLastSequence, NATS_EXPECTED_LAST_SEQUENCE, b"Nats-Expected-Last-Sequence");
    /// The expected stream the message should be part of.
    (NatsExpectedStream, NATS_EXPECTED_STREAM, b"Nats-Expected-Stream");
    /// Sets the TTL for a single message.
    (NatsMessageTtl, NATS_MESSAGE_TTL, b"Nats-TTL");
    /// Reason why the delete marked on a stream with enabled markers was put.
    (NatsMarkerReason, NATS_MARKER_REASON, b"Nats-Marker-Reason");
    /// Initiates a rollup of the given subject(s); valid values are `sub` and `all`.
    (NatsRollup, NATS_ROLLUP, b"Nats-Rollup");
    /// Schedule expression for a JetStream message scheduler entry. ADR-51.
    (NatsSchedule, NATS_SCHEDULE, b"Nats-Schedule");
    /// Target subject the schedule publishes to.
    (NatsScheduleTarget, NATS_SCHEDULE_TARGET, b"Nats-Schedule-Target");
    /// TTL applied to messages produced by the schedule.
    (NatsScheduleTtl, NATS_SCHEDULE_TTL, b"Nats-Schedule-TTL");
    /// Source subject sampled into the schedule output.
    (NatsScheduleSource, NATS_SCHEDULE_SOURCE, b"Nats-Schedule-Source");
    /// Time zone for cron schedules. Accepts IANA names like `America/New_York`.
    (NatsScheduleTimeZone, NATS_SCHEDULE_TIME_ZONE, b"Nats-Schedule-Time-Zone");
    /// Auto-applies a rollup on the schedule target. Currently only `sub` is valid.
    (NatsScheduleRollup, NATS_SCHEDULE_ROLLUP, b"Nats-Schedule-Rollup");
    /// On schedule-produced messages: the subject of the originating schedule.
    (NatsScheduler, NATS_SCHEDULER, b"Nats-Scheduler");
    /// On schedule-produced messages: timestamp of next firing or `purge` for delayed schedules.
    (NatsScheduleNext, NATS_SCHEDULE_NEXT, b"Nats-Schedule-Next");
    /// Atomic batch publish: batch id (max 64 chars).
    (NatsBatchId, NATS_BATCH_ID, b"Nats-Batch-Id");
    /// Atomic batch publish: per-message sequence within the batch.
    (NatsBatchSequence, NATS_BATCH_SEQUENCE, b"Nats-Batch-Sequence");
    /// Atomic batch publish: commit marker. `1` to commit and store the final
    /// message; `eob` to commit without storing it (end-of-batch).
    (NatsBatchCommit, NATS_BATCH_COMMIT, b"Nats-Batch-Commit");
    /// Minimum JetStream API level the publishing client requires; the server
    /// will reject the message (and the enclosing batch, if any) when its own
    /// level is below the value set here.
    (NatsRequiredApiLevel, NATS_REQUIRED_API_LEVEL, b"Nats-Required-Api-Level");
}

/// Value constant for [`NATS_BATCH_COMMIT`]: commit and store the final message.
pub const NATS_BATCH_COMMIT_FINAL: &str = "1";
/// Value constant for [`NATS_BATCH_COMMIT`]: commit without storing the final
/// message (end-of-batch). Server is case-sensitive on this string.
pub const NATS_BATCH_COMMIT_EOB: &str = "eob";
/// Value constant for [`NATS_SCHEDULE_ROLLUP`]: rollup the schedule's target
/// subject. Currently the only legal value.
pub const NATS_SCHEDULE_ROLLUP_SUB: &str = "sub";

/// Predefined [`NATS_SCHEDULE`] expression: run once a year at midnight Jan 1.
pub const NATS_SCHEDULE_YEARLY: &str = "@yearly";
/// Predefined [`NATS_SCHEDULE`] expression: run once a month at midnight on the 1st.
pub const NATS_SCHEDULE_MONTHLY: &str = "@monthly";
/// Predefined [`NATS_SCHEDULE`] expression: run once a week at midnight Sat→Sun.
pub const NATS_SCHEDULE_WEEKLY: &str = "@weekly";
/// Predefined [`NATS_SCHEDULE`] expression: run once a day at midnight.
pub const NATS_SCHEDULE_DAILY: &str = "@daily";
/// Predefined [`NATS_SCHEDULE`] expression: run once an hour at the top of the hour.
pub const NATS_SCHEDULE_HOURLY: &str = "@hourly";

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct HeaderText {
    bytes: Bytes,
}

impl HeaderText {
    #[inline]
    pub(crate) const fn from_static(value: &'static str) -> HeaderText {
        HeaderText {
            bytes: Bytes::from_static(value.as_bytes()),
        }
    }

    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        // Every constructor takes a string or a fully validated received block. Folding copies
        // complete UTF-8 slices at ASCII delimiters, and publication makes these bytes immutable.
        unsafe { std::str::from_utf8_unchecked(self.bytes.as_ref()) }
    }
}

impl From<String> for HeaderText {
    #[inline]
    fn from(value: String) -> HeaderText {
        HeaderText {
            bytes: Bytes::from(value),
        }
    }
}

impl<'a> From<&'a str> for HeaderText {
    #[inline]
    fn from(value: &'a str) -> HeaderText {
        HeaderText {
            bytes: Bytes::copy_from_slice(value.as_bytes()),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
enum HeaderRepr {
    Standard(StandardHeader),
    Custom(HeaderText),
}

/// Defines a NATS header field name
///
/// Header field names identify the header. Header sets may include multiple
/// headers with the same name.
///
/// # Representation
///
/// `HeaderName` represents standard header names using an `enum`, as such they
/// will not require an allocation for storage.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct HeaderName {
    inner: HeaderRepr,
}

impl HeaderName {
    /// Converts a static string to a NATS header name.
    #[inline]
    pub const fn from_static(value: &'static str) -> HeaderName {
        if let Some(standard) = StandardHeader::from_bytes(value.as_bytes()) {
            return HeaderName {
                inner: HeaderRepr::Standard(standard),
            };
        }

        HeaderName {
            inner: HeaderRepr::Custom(HeaderText::from_static(value)),
        }
    }

    /// Returns a `str` representation of the header.
    #[inline]
    fn as_str(&self) -> &str {
        match self.inner {
            HeaderRepr::Standard(v) => v.as_str(),
            HeaderRepr::Custom(ref v) => v.as_str(),
        }
    }
}

impl FromStr for HeaderName {
    type Err = ParseHeaderNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_header_name(s)?;
        Ok(match StandardHeader::from_bytes(s.as_bytes()) {
            Some(v) => HeaderName {
                inner: HeaderRepr::Standard(v),
            },
            None => HeaderName {
                inner: HeaderRepr::Custom(HeaderText::from(s)),
            },
        })
    }
}

/// Fallible conversion from a borrowed string slice; validates the name without panicking.
impl TryFrom<&str> for HeaderName {
    type Error = ParseHeaderNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// Fallible conversion from an owned `String`; validates without panicking and
/// avoids re-allocating the bytes when the result is a custom (non-standard) name.
impl TryFrom<String> for HeaderName {
    type Error = ParseHeaderNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_header_name(&value)?;
        Ok(match StandardHeader::from_bytes(value.as_bytes()) {
            Some(v) => HeaderName {
                inner: HeaderRepr::Standard(v),
            },
            None => HeaderName {
                inner: HeaderRepr::Custom(HeaderText::from(value)),
            },
        })
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_str(), f)
    }
}

impl AsRef<[u8]> for HeaderName {
    fn as_ref(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl AsRef<str> for HeaderName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for HeaderName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HeaderName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone)]
pub struct ParseHeaderNameError;

impl std::fmt::Display for ParseHeaderNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid header name (name cannot contain non-ascii alphanumeric characters other than '-')")
    }
}

impl std::error::Error for ParseHeaderNameError {}

fn validate_header_name(s: &str) -> Result<(), ParseHeaderNameError> {
    if s.contains(|c: char| !c.is_ascii_graphic() || c == ':') {
        Err(ParseHeaderNameError)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{HeaderMap, HeaderName, HeaderValue, IntoHeaderName, IntoHeaderValue};
    use std::str::{from_utf8, FromStr};

    #[test]
    fn transport_projection_keeps_the_indexed_map_footprint() {
        assert_eq!(
            std::mem::size_of::<HeaderMap>(),
            std::mem::size_of::<std::collections::HashMap<HeaderName, Vec<HeaderValue>>>()
        );
    }

    #[test]
    fn owned_transport_pairs_move_without_copying_or_wire_allocation() {
        for (names, repeats, name_len) in [(1, 1, 3), (1, 32, 8192), (16, 1, 3), (4, 8, 3)] {
            let input = (0..names)
                .flat_map(|name| {
                    (0..repeats).map(move |_| {
                        (
                            format!("X-{name}{}", "n".repeat(name_len)),
                            "value".to_owned(),
                        )
                    })
                })
                .collect::<Vec<_>>();
            let pointer = input.as_ptr();
            let mut retained = None;
            let allocated = allocation_counter::measure(|| {
                let headers = HeaderMap::from_ordered(input);
                assert_eq!(headers.iter_ordered().count(), names * repeats);
                std::hint::black_box(headers.wire_len());
                retained = Some(headers);
            });
            assert_eq!(allocated.count_total, 1);
            assert_eq!(
                allocated.bytes_total,
                (std::mem::size_of::<super::HeaderProjection>() + 2 * std::mem::size_of::<usize>())
                    as u64
            );
            let super::HeaderStorage::Projection(projection) = &retained.as_ref().unwrap().inner
            else {
                panic!("ordered projection");
            };
            let super::TransportHeaders::Ordered(pairs) = &projection.data else {
                panic!("ordered pairs");
            };
            assert_eq!(pairs.pairs.as_ptr(), pointer);
            assert!(projection.indexed.get().is_none());
            let borrowed = allocation_counter::measure(|| {
                std::hint::black_box(retained.as_ref().unwrap().clone());
                std::hint::black_box(retained.as_ref().unwrap().iter_ordered().count());
            });
            assert_eq!(borrowed.count_total, 0);
        }
    }

    #[test]
    fn received_transport_headers_share_the_existing_frame_even_with_empty_payload() {
        let name = format!("X-{}", "n".repeat(8192));
        let wire = format!(
            "NATS/1.0\r\n{}\r\n",
            format!("{name}: value\r\n").repeat(32)
        );
        let mut frame = bytes::BytesMut::from(wire.as_bytes());
        let block = frame.split_to(wire.len());
        let pointer = block.as_ptr();
        let payload = frame.split_to(0).freeze();
        let mut retained = None;
        let allocated = allocation_counter::measure(|| {
            let headers = HeaderMap::from_received(block).unwrap();
            assert_eq!(headers.iter_ordered().count(), 32);
            retained = Some(headers);
        });
        assert!(allocated.count_total <= 6);
        assert!(
            allocated.bytes_total
                <= (2 * 32 * std::mem::size_of::<super::HeaderIndex>()
                    + std::mem::size_of::<super::HeaderProjection>()
                    + 2 * std::mem::size_of::<usize>()) as u64
        );
        let super::HeaderStorage::Projection(projection) = &retained.as_ref().unwrap().inner else {
            panic!("received block");
        };
        let super::TransportHeaders::Received(block) = &projection.data else {
            panic!("received bytes");
        };
        assert_eq!(block.text.bytes.as_ptr(), pointer);
        assert!(projection.indexed.get().is_none());
        let borrowed = allocation_counter::measure(|| {
            std::hint::black_box(retained.as_ref().unwrap().get_str("missing"));
            std::hint::black_box(retained.as_ref().unwrap().iter_ordered().count());
        });
        assert_eq!(borrowed.count_total, 0);
        drop(frame);
        assert!(!payload.is_unique());
        drop(retained);
        assert!(payload.is_unique());
    }

    #[test]
    fn received_folding_preserves_leading_continuation_space_and_empty_values() {
        let wire = b"NATS/1.0\r\nfirst:   one  \r\n  continued \r\nsecond:  \r\n  after-empty  \r\nfirst: three  \r\nempty:\r\n\r\n";
        let headers = HeaderMap::from_received(bytes::BytesMut::from(wire.as_slice())).unwrap();
        assert_eq!(
            headers.iter_ordered().collect::<Vec<_>>(),
            [
                ("first", "one    continued"),
                ("second", "  after-empty"),
                ("first", "three"),
                ("empty", "")
            ]
        );
        assert_eq!(headers.get_str("second"), Some("  after-empty"));
        assert_eq!(
            headers
                .get_all("first")
                .map(HeaderValue::as_str)
                .collect::<Vec<_>>(),
            ["one    continued", "three"]
        );
        assert_eq!(headers.wire_len(), headers.to_bytes().len());
    }

    #[test]
    fn stream_transport_overrides_reserved_exact_names_and_preserves_other_repeats() {
        let pairs = [
            ("first", "one"),
            ("Nats-Expected-Stream", "ignored"),
            ("Nats-Msg-Id", "ignored-id"),
            ("nats-msg-id", "case-sensitive"),
            ("second", "two"),
            ("first", "three"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
        let headers = HeaderMap::from_ordered_with_stream(
            pairs,
            Some("message-id".to_owned()),
            "EVENTS".to_owned(),
        );
        assert_eq!(
            headers.iter_ordered().collect::<Vec<_>>(),
            [
                ("first", "one"),
                ("nats-msg-id", "case-sensitive"),
                ("second", "two"),
                ("first", "three"),
                ("Nats-Msg-Id", "message-id"),
                ("Nats-Expected-Stream", "EVENTS")
            ]
        );
        assert_eq!(headers.wire_len(), headers.to_bytes().len());
    }

    #[test]
    fn ordered_admission_allocates_less_than_indexed_authoring_for_populated_shapes() {
        for (names, repeats, name_len, value_len) in [
            (1, 1, 3, 5),
            (1, 32, 8192, 5),
            (16, 1, 3, 5),
            (4, 8, 3, 5),
            (1, 1, 3, 65536),
        ] {
            let input = (0..names)
                .flat_map(|name| {
                    (0..repeats).map(move |_| {
                        (
                            format!("X-{name}{}", "n".repeat(name_len)),
                            "v".repeat(value_len),
                        )
                    })
                })
                .collect::<Vec<_>>();
            let mut indexed = None;
            let indexed_cost = allocation_counter::measure(|| {
                let mut headers = HeaderMap::new();
                for (name, value) in &input {
                    headers.append(name.as_str(), value.as_str());
                }
                std::hint::black_box(headers.wire_len());
                indexed = Some(headers);
            });
            let mut ordered = None;
            let ordered_cost = allocation_counter::measure(|| {
                let headers = HeaderMap::from_ordered(input);
                std::hint::black_box(headers.wire_len());
                ordered = Some(headers);
            });
            println!("shape names={names} repeats={repeats} name_len={name_len} value_len={value_len}: indexed={indexed_cost:?}; ordered={ordered_cost:?}");
            assert!(ordered_cost.count_total < indexed_cost.count_total);
            assert!(ordered_cost.bytes_total < indexed_cost.bytes_total);
            assert_eq!(
                ordered.as_ref().unwrap().wire_len(),
                indexed.as_ref().unwrap().wire_len()
            );
        }
    }

    #[test]
    fn malformed_received_names_values_and_utf8_keep_their_typed_cause() {
        for wire in [
            b"NATS/1.0\r\nBad Name: x\r\n\r\n".as_slice(),
            b"NATS/1.0\r\nvalid: embedded\rcarriage\r\n\r\n".as_slice(),
            b"NATS/1.0\r\nvalid: \xff\r\n\r\n".as_slice(),
        ] {
            let error = HeaderMap::from_received(bytes::BytesMut::from(wire)).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.get_ref().is_some());
        }
    }

    #[test]
    fn allocations_empty_maps_and_their_clones_need_no_storage() {
        let allocated = allocation_counter::measure(|| {
            let headers = std::hint::black_box(HeaderMap::new());
            std::hint::black_box(headers.clone());
        });
        assert_eq!(allocated.count_total, 0);
    }

    #[test]
    fn allocations_serialization_streams_each_names_values() {
        let mut headers = HeaderMap::new();
        headers.append("first", "one");
        headers.append("second", "two");
        headers.append("first", "three");
        let allocated = allocation_counter::measure(|| {
            serde_json::to_writer(std::io::sink(), &headers).expect("valid header values");
        });
        assert_eq!(allocated.count_total, 0);
    }

    #[test]
    fn an_empty_json_header_key_keeps_its_presence_and_accepts_values() {
        let mut headers: HeaderMap = serde_json::from_str(r#"{"empty":[]}"#).unwrap();
        assert_eq!(headers.len(), 1);
        assert!(!headers.is_empty());
        assert_eq!(headers.get_all("empty").count(), 0);
        assert_eq!(
            serde_json::to_value(&headers).unwrap(),
            serde_json::json!({"empty": []})
        );
        let other: HeaderMap = serde_json::from_str(r#"{"different":[]}"#).unwrap();
        assert_ne!(headers, other);
        headers.append("empty", "first");
        assert_eq!(headers.get("empty").unwrap().as_str(), "first");
        assert_eq!(
            headers
                .get_all("empty")
                .map(HeaderValue::as_str)
                .collect::<Vec<_>>(),
            ["first"]
        );
        assert_eq!(headers.to_bytes(), b"NATS/1.0\r\nempty: first\r\n\r\n");
    }

    #[test]
    fn interleaved_headers_keep_wire_order() {
        let headers = HeaderMap::from_ordered(
            [("first", "one"), ("second", "two"), ("first", "three")]
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        );
        assert_eq!(
            headers.to_bytes(),
            b"NATS/1.0\r\nfirst: one\r\nsecond: two\r\nfirst: three\r\n\r\n"
        );
        assert_eq!(headers.wire_len(), headers.to_bytes().len());
    }

    #[test]
    fn try_from() {
        let mut headers = HeaderMap::new();
        headers.insert("name", "something".parse::<HeaderValue>().unwrap());
        headers.insert("name", "something2");
    }

    #[test]
    fn append() {
        let mut headers = HeaderMap::new();
        headers.append("Key", "value");
        headers.append("Key", "second_value");

        let mut result = headers.get_all("Key");

        assert_eq!(
            result.next().unwrap(),
            &HeaderValue::from_str("value").unwrap()
        );

        assert_eq!(
            result.next().unwrap(),
            &HeaderValue::from_str("second_value").unwrap()
        );

        assert_eq!(result.next(), None);
    }

    #[test]
    fn get_string() {
        let mut headers = HeaderMap::new();
        headers.append("Key", "value");
        headers.append("Key", "other");

        assert_eq!(headers.get("Key").unwrap().to_string(), "value");

        let key: String = headers.get("Key").unwrap().as_str().into();
        assert_eq!(key, "value".to_string());

        let key: String = headers.get("Key").unwrap().as_str().to_owned();
        assert_eq!(key, "value".to_string());

        assert_eq!(headers.get("Key").unwrap().as_str(), "value");

        let key: String = headers.get_last("Key").unwrap().as_str().into();
        assert_eq!(key, "other".to_string());
    }

    #[test]
    fn insert() {
        let mut headers = HeaderMap::new();
        headers.insert("Key", "Value");

        let mut result = headers.get_all("Key");

        assert_eq!(
            result.next().unwrap(),
            &HeaderValue::from_str("Value").unwrap()
        );
        assert_eq!(result.next(), None);
    }

    #[test]
    fn serialize() {
        let mut headers = HeaderMap::new();
        headers.append("Key", "value");
        headers.append("Key", "second_value");
        headers.insert("Second", "SecondValue");

        let bytes = headers.to_bytes();

        println!("bytes: {:?}", from_utf8(&bytes));
    }

    #[test]
    fn wire_len_matches_serialized() {
        let mut headers = HeaderMap::new();
        headers.append("Key", "value");
        headers.append("Key", "second_value");
        headers.insert("Second", "SecondValue");
        assert_eq!(headers.wire_len(), headers.to_bytes().len());

        // An empty block still serializes the framing bytes.
        let empty = HeaderMap::new();
        assert_eq!(empty.wire_len(), empty.to_bytes().len());
    }

    #[test]
    fn is_empty() {
        let mut headers = HeaderMap::new();
        assert!(headers.is_empty());

        headers.append("Key", "value");
        headers.append("Key", "second_value");
        headers.insert("Second", "SecondValue");
        assert!(!headers.is_empty());
    }

    #[test]
    fn parse_value() {
        assert!("Foo\r".parse::<HeaderValue>().is_err());
        assert!("Foo\n".parse::<HeaderValue>().is_err());
        assert!("Foo\r\n".parse::<HeaderValue>().is_err());
    }

    #[test]
    fn valid_header_name() {
        let valid_header_name = "X-Custom-Header";
        let parsed_header = HeaderName::from_str(valid_header_name);

        assert!(
            parsed_header.is_ok(),
            "Expected Ok(HeaderName), but got an error: {:?}",
            parsed_header.err()
        );
    }

    #[test]
    fn dollar_header_name() {
        let valid_header_name = "$X_Custom_Header";
        let parsed_header = HeaderName::from_str(valid_header_name);

        assert!(
            parsed_header.is_ok(),
            "Expected Ok(HeaderName), but got an error: {:?}",
            parsed_header.err()
        );
    }

    #[test]
    fn invalid_header_name_with_space() {
        let invalid_header_name = "X Custom Header";
        let parsed_header = HeaderName::from_str(invalid_header_name);

        assert!(
            parsed_header.is_err(),
            "Expected Err(InvalidHeaderNameError), but got Ok: {:?}",
            parsed_header.ok()
        );
    }

    #[test]
    fn invalid_header_name_with_special_chars() {
        let invalid_header_name = "X-Header:";
        let parsed_header = HeaderName::from_str(invalid_header_name);

        assert!(
            parsed_header.is_err(),
            "Expected Err(InvalidHeaderNameError), but got Ok: {:?}",
            parsed_header.ok()
        );
    }

    #[test]
    fn from_static_eq() {
        let a = HeaderName::from_static("NATS-Stream");
        let b = HeaderName::from_static("NATS-Stream");

        assert_eq!(a, b);
    }

    #[test]
    fn header_name_serde() {
        let raw = "Nats-Stream";
        let raw_json = "\"Nats-Stream\"";
        let header = HeaderName::from_static(raw);

        // ser/de of HeaderName should be the same as raw string
        assert_eq!(serde_json::to_string(&header).unwrap(), raw_json);
        assert_eq!(
            serde_json::from_str::<HeaderName>(raw_json).unwrap(),
            header
        );
    }

    #[test]
    fn header_name_from_string() {
        let string = "NATS-Stream".to_string();
        let name = string.into_header_name();

        assert_eq!("NATS-Stream", name.as_str());
    }

    #[test]
    fn header_value_from_string_with_trait() {
        let string = "some value".to_string();

        let value = string.into_header_value();

        assert_eq!("some value", value.as_str());
    }

    #[test]
    fn header_value_from_string() {
        let string = "some value".to_string();

        let value: HeaderValue = string.into();

        assert_eq!("some value", value.as_str());
    }

    #[test]
    fn header_map_backward_compatible_deserialization() {
        // Test new format (direct HashMap) - this is how it should serialize now
        let new_format_json =
            r#"{"Content-Type": ["application/json"], "Authorization": ["Bearer token"]}"#;
        let header_map: HeaderMap = serde_json::from_str(new_format_json).unwrap();

        assert_eq!(
            header_map.get("Content-Type").unwrap().as_str(),
            "application/json"
        );
        assert_eq!(
            header_map.get("Authorization").unwrap().as_str(),
            "Bearer token"
        );

        // Test legacy format (with "inner" wrapper) - this is the old format that should still work
        let legacy_format_json = r#"{"inner": {"Content-Type": ["application/json"], "Authorization": ["Bearer token"]}}"#;
        let header_map_legacy: HeaderMap = serde_json::from_str(legacy_format_json).unwrap();

        assert_eq!(
            header_map_legacy.get("Content-Type").unwrap().as_str(),
            "application/json"
        );
        assert_eq!(
            header_map_legacy.get("Authorization").unwrap().as_str(),
            "Bearer token"
        );

        // Both should be equal after deserialization
        assert_eq!(header_map, header_map_legacy);
    }

    #[test]
    fn header_map_serialization_new_format() {
        // Test that serialization uses the new format (no "inner" wrapper)
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");
        headers.insert("Authorization", "Bearer token");

        let serialized = serde_json::to_string(&headers).unwrap();

        // Should not contain "inner" key
        assert!(!serialized.contains("inner"));

        // Should be able to deserialize back
        let deserialized: HeaderMap = serde_json::from_str(&serialized).unwrap();
        assert_eq!(headers, deserialized);
    }

    #[test]
    fn header_map_roundtrip_compatibility() {
        // Test that we can roundtrip both formats
        let mut original = HeaderMap::new();
        original.insert("X-Custom-Header", "custom-value");
        original.append("Multi-Value", "value1");
        original.append("Multi-Value", "value2");

        // Serialize using new format
        let new_serialized = serde_json::to_string(&original).unwrap();
        let new_deserialized: HeaderMap = serde_json::from_str(&new_serialized).unwrap();
        assert_eq!(original, new_deserialized);

        // Manually create legacy format JSON
        let legacy_json = format!(r#"{{"inner": {}}}"#, new_serialized);
        let legacy_deserialized: HeaderMap = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(original, legacy_deserialized);
    }

    #[test]
    fn header_map_invalid_format_error() {
        // Test that invalid JSON returns proper error
        let invalid_json = r#"{"not_inner_or_direct": {"Content-Type": ["application/json"]}}"#;
        let result = serde_json::from_str::<HeaderMap>(invalid_json);
        assert!(result.is_err());

        let error_message = result.unwrap_err().to_string();
        // With untagged enum, serde will report that data doesn't match any variant
        assert!(error_message.contains("did not match any variant"));
    }

    #[test]
    fn header_map_empty_cases() {
        // Test empty HeaderMap serialization/deserialization
        let empty = HeaderMap::new();
        let serialized = serde_json::to_string(&empty).unwrap();
        assert_eq!(serialized, "{}");

        let deserialized: HeaderMap = serde_json::from_str("{}").unwrap();
        assert!(deserialized.is_empty());

        // Test legacy empty format
        let legacy_empty = r#"{"inner": {}}"#;
        let legacy_deserialized: HeaderMap = serde_json::from_str(legacy_empty).unwrap();
        assert!(legacy_deserialized.is_empty());
    }

    #[test]
    fn header_map_mixed_legacy_detection() {
        // Test that an "inner" header name doesn't confuse the deserializer
        // This would be a new format where "inner" is a legitimate header name
        let json_with_inner_header =
            r#"{"inner": ["some-value"], "Other-Header": ["other-value"]}"#;
        let header_map: HeaderMap = serde_json::from_str(json_with_inner_header).unwrap();

        // Should have two headers
        assert_eq!(header_map.len(), 2);
        assert_eq!(header_map.get("inner").unwrap().as_str(), "some-value");
        assert_eq!(
            header_map.get("Other-Header").unwrap().as_str(),
            "other-value"
        );
    }

    #[test]
    #[should_panic(expected = "invalid header value")]
    fn header_value_from_str_rejects_cr() {
        let _: HeaderValue = "value\rwith\rcr".into();
    }

    #[test]
    #[should_panic(expected = "invalid header value")]
    fn header_value_from_str_rejects_lf() {
        let _: HeaderValue = "value\nwith\nlf".into();
    }

    #[test]
    #[should_panic(expected = "invalid header value")]
    fn header_value_from_string_rejects_crlf() {
        let _: HeaderValue = "injected\r\nPUB attack 0\r\n\r\n".to_string().into();
    }

    #[test]
    #[should_panic(expected = "invalid header value")]
    fn header_value_into_trait_rejects_crlf() {
        let mut headers = HeaderMap::new();
        headers.insert("Key", "value\r\nPUB attack 0\r\n\r\n");
    }

    #[test]
    #[should_panic(expected = "invalid header name")]
    fn header_name_into_trait_rejects_cr() {
        let mut headers = HeaderMap::new();
        headers.insert("Bad\rName", "value");
    }

    #[test]
    #[should_panic(expected = "invalid header name")]
    fn header_name_into_trait_rejects_lf() {
        let mut headers = HeaderMap::new();
        headers.insert("Bad\nName", "value");
    }

    #[test]
    #[should_panic(expected = "invalid header name")]
    fn header_name_into_trait_rejects_space() {
        let mut headers = HeaderMap::new();
        headers.insert("Bad Name", "value");
    }

    #[test]
    #[should_panic(expected = "invalid header name")]
    fn header_name_into_trait_rejects_colon() {
        let mut headers = HeaderMap::new();
        headers.insert("Bad:Name", "value");
    }

    #[test]
    #[should_panic(expected = "invalid header name")]
    fn header_name_from_string_rejects_control_chars() {
        let name = "Bad\x00Name".to_string();
        name.into_header_name();
    }

    #[test]
    fn valid_header_values_still_work() {
        let _: HeaderValue = "normal value".into();
        let _: HeaderValue = "value with special chars !@#$%^&*()".into();
        let _: HeaderValue = "".into();
        let _: HeaderValue = String::from("string value").into();
    }

    #[test]
    fn header_name_try_from_str() {
        assert_eq!(
            HeaderName::try_from("X-Custom").unwrap().as_str(),
            "X-Custom"
        );
        assert!(HeaderName::try_from("Bad Name").is_err());
        assert!(HeaderName::try_from("Bad:Name").is_err());
    }

    #[test]
    fn header_name_try_from_string() {
        assert_eq!(
            HeaderName::try_from("Nats-Stream".to_string())
                .unwrap()
                .as_str(),
            "Nats-Stream"
        );
        assert!(HeaderName::try_from("Bad\nName".to_string()).is_err());
    }

    #[test]
    fn valid_header_names_still_work() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Custom-Header", "value");
        headers.insert("Another-Header", "value");
        headers.insert("$dollar", "value");
        headers.insert("Nats-Stream", "value");
        assert_eq!(headers.get("Nats-Stream").unwrap().as_str(), "value");
    }

    #[test]
    fn header_map_large_headers() {
        // Test with many headers
        let mut headers = HeaderMap::new();
        for i in 0..100 {
            headers.insert(format!("Header-{}", i), format!("Value-{}", i));
        }

        let serialized = serde_json::to_string(&headers).unwrap();
        let deserialized: HeaderMap = serde_json::from_str(&serialized).unwrap();

        assert_eq!(headers.len(), deserialized.len());
        for i in 0..100 {
            assert_eq!(
                deserialized
                    .get(format!("Header-{}", i).as_str())
                    .unwrap()
                    .as_str(),
                format!("Value-{}", i)
            );
        }
    }
}
