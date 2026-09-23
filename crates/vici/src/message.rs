//! strongSwan vici protocol (src/libcharon/plugins/vici/README.md in
//! strongSwan): message encoding.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, MESSAGE_SIZE_MAX, Result};

const SECTION_START: u8 = 1;
const SECTION_END: u8 = 2;
const KEY_VALUE: u8 = 3;
const LIST_START: u8 = 4;
const LIST_ITEM: u8 = 5;
const LIST_END: u8 = 6;

/// Path component matching the first section or list of any name.
pub const ANY: &str = "*";

/// Deepest section nesting accepted from the wire; charon's own messages
/// stay below ten levels.
const MAX_DEPTH: usize = 64;

/// One element of a [`Section`].
///
/// Values are kept as raw bytes: charon uses non-terminated strings, but the
/// protocol allows arbitrary blobs (certificates, keys). Messages may carry
/// secrets, so they are wiped when dropped.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Item {
    /// A named sub-section.
    Section { name: String, body: Section },
    /// A key with a single value.
    KeyValue {
        /// Key name, unique in its section.
        key: String,
        value: Vec<u8>,
    },
    /// A named list of values.
    List { name: String, items: Vec<Vec<u8>> },
}

impl Item {
    fn name(&self) -> &str {
        match self {
            Item::Section { name, .. } | Item::List { name, .. } => name,
            Item::KeyValue { key, .. } => key,
        }
    }

    fn is_container(&self) -> bool {
        matches!(self, Item::Section { .. } | Item::List { .. })
    }
}

/// An ordered tree of message elements: the implicit root of a message or a
/// named sub-section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Section {
    items: Vec<Item>,
}

impl Section {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a key/value pair.
    #[must_use]
    pub fn kv(mut self, key: impl Into<String>, value: impl AsRef<[u8]>) -> Self {
        self.items.push(Item::KeyValue {
            key: key.into(),
            value: value.as_ref().to_vec(),
        });
        self
    }

    #[must_use]
    pub fn list<I, T>(mut self, name: impl Into<String>, items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.items.push(Item::List {
            name: name.into(),
            items: items
                .into_iter()
                .map(|item| item.as_ref().to_vec())
                .collect(),
        });
        self
    }

    #[must_use]
    pub fn section(mut self, name: impl Into<String>, body: Section) -> Self {
        self.items.push(Item::Section {
            name: name.into(),
            body,
        });
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Looks an element up by path. [`ANY`] matches the first section or
    /// list of any name, e.g. `["child-sas", ANY, "remote-ts"]`.
    #[must_use]
    pub fn get(&self, path: &[&str]) -> Option<&Item> {
        let (first, rest) = path.split_first()?;
        let item = self.items.iter().find(|item| {
            if *first == ANY {
                item.is_container()
            } else {
                item.name() == *first
            }
        })?;
        if rest.is_empty() {
            return Some(item);
        }
        match item {
            Item::Section { body, .. } => body.get(rest),
            Item::KeyValue { .. } | Item::List { .. } => None,
        }
    }

    /// The value of a key/value element as UTF-8 text.
    #[must_use]
    pub fn get_str(&self, path: &[&str]) -> Option<&str> {
        match self.get(path)? {
            Item::KeyValue { value, .. } => std::str::from_utf8(value).ok(),
            Item::Section { .. } | Item::List { .. } => None,
        }
    }

    #[must_use]
    pub fn get_section(&self, path: &[&str]) -> Option<&Section> {
        match self.get(path)? {
            Item::Section { body, .. } => Some(body),
            Item::KeyValue { .. } | Item::List { .. } => None,
        }
    }

    #[must_use]
    pub fn get_list(&self, path: &[&str]) -> Option<&[Vec<u8>]> {
        match self.get(path)? {
            Item::List { items, .. } => Some(items),
            Item::Section { .. } | Item::KeyValue { .. } => None,
        }
    }

    /// The items of a list as UTF-8 text, skipping non-text values.
    pub fn get_str_list(&self, path: &[&str]) -> impl Iterator<Item = &str> {
        self.get_list(path)
            .unwrap_or_default()
            .iter()
            .filter_map(|item| std::str::from_utf8(item).ok())
    }

    /// Iterates over the direct sub-sections.
    pub fn sections(&self) -> impl Iterator<Item = (&str, &Section)> {
        self.items.iter().filter_map(|item| match item {
            Item::Section { name, body } => Some((name.as_str(), body)),
            Item::KeyValue { .. } | Item::List { .. } => None,
        })
    }

    /// Serializes the section into the wire format (without any packet
    /// framing).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        if out.len() > MESSAGE_SIZE_MAX {
            return Err(Error::MessageSize(out.len()));
        }
        Ok(out)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        for item in &self.items {
            match item {
                Item::Section { name, body } => {
                    out.push(SECTION_START);
                    put_name(out, name)?;
                    body.encode_into(out)?;
                    out.push(SECTION_END);
                }
                Item::KeyValue { key, value } => {
                    out.push(KEY_VALUE);
                    put_name(out, key)?;
                    put_value(out, value)?;
                }
                Item::List { name, items } => {
                    out.push(LIST_START);
                    put_name(out, name)?;
                    for value in items {
                        out.push(LIST_ITEM);
                        put_value(out, value)?;
                    }
                    out.push(LIST_END);
                }
            }
        }
        Ok(())
    }

    /// Parses a section from the wire format.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() > MESSAGE_SIZE_MAX {
            return Err(Error::MessageSize(data.len()));
        }
        let mut reader = Reader { data, pos: 0 };
        // Sections under construction, innermost last; the root is at index 0.
        let mut stack: Vec<(String, Section)> = vec![(String::new(), Section::new())];
        let mut list: Option<(String, Vec<Vec<u8>>)> = None;

        while let Some(kind) = reader.next_byte() {
            match kind {
                SECTION_START => {
                    if list.is_some() {
                        return Err(Error::Malformed("section inside a list"));
                    }
                    if stack.len() > MAX_DEPTH {
                        return Err(Error::Malformed("section nesting too deep"));
                    }
                    let name = reader.name()?;
                    stack.push((name, Section::new()));
                }
                SECTION_END => {
                    if list.is_some() {
                        return Err(Error::Malformed("unterminated list"));
                    }
                    if stack.len() < 2 {
                        return Err(Error::Malformed("unbalanced section end"));
                    }
                    let (name, body) = stack.pop().unwrap_or_default();
                    push_item(&mut stack, Item::Section { name, body });
                }
                KEY_VALUE => {
                    if list.is_some() {
                        return Err(Error::Malformed("key/value inside a list"));
                    }
                    let key = reader.name()?;
                    let value = reader.value()?;
                    push_item(&mut stack, Item::KeyValue { key, value });
                }
                LIST_START => {
                    if list.is_some() {
                        return Err(Error::Malformed("nested list"));
                    }
                    list = Some((reader.name()?, Vec::new()));
                }
                LIST_ITEM => {
                    let value = reader.value()?;
                    match list.as_mut() {
                        Some((_, items)) => items.push(value),
                        None => return Err(Error::Malformed("list item outside a list")),
                    }
                }
                LIST_END => match list.take() {
                    Some((name, items)) => push_item(&mut stack, Item::List { name, items }),
                    None => return Err(Error::Malformed("list end without list")),
                },
                other => {
                    return Err(Error::UnknownType {
                        kind: "element",
                        value: other,
                    });
                }
            }
        }
        if list.is_some() {
            return Err(Error::Malformed("unterminated list"));
        }
        if stack.len() != 1 {
            return Err(Error::Malformed("unterminated section"));
        }
        Ok(stack.pop().unwrap_or_default().1)
    }
}

fn push_item(stack: &mut [(String, Section)], item: Item) {
    if let Some((_, section)) = stack.last_mut() {
        section.items.push(item);
    }
}

/// Writes an element name: 8-bit length followed by the bytes.
pub(crate) fn put_name(out: &mut Vec<u8>, name: &str) -> Result<()> {
    let len = name.len();
    if len == 0 || len > usize::from(u8::MAX) {
        return Err(Error::NameLength(len));
    }
    out.push(u8::try_from(len).map_err(|_| Error::NameLength(len))?);
    out.extend_from_slice(name.as_bytes());
    Ok(())
}

/// Writes a value: 16-bit big endian length followed by the bytes.
fn put_value(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u16::try_from(value.len()).map_err(|_| Error::ValueLength(value.len()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Cursor over incoming bytes.
pub(crate) struct Reader<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) pos: usize,
}

impl Reader<'_> {
    pub(crate) fn next_byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn take(&mut self, len: usize) -> Result<&[u8]> {
        let end = self.pos.checked_add(len).ok_or(Error::Truncated)?;
        let slice = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn name(&mut self) -> Result<String> {
        let len = usize::from(self.next_byte().ok_or(Error::Truncated)?);
        let bytes = self.take(len)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    fn value(&mut self) -> Result<Vec<u8>> {
        let len = self.take(2)?;
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        Ok(self.take(len)?.to_vec())
    }

    pub(crate) fn rest(&self) -> &[u8] {
        self.data.get(self.pos..).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Section {
        Section::new()
            .section(
                "conn",
                Section::new()
                    .kv("version", "2")
                    .list("remote_addrs", ["vpn.example.com", "10.0.0.1"])
                    .section(
                        "children",
                        Section::new().section(
                            "net",
                            Section::new().kv("dpd_delay", "30s").kv("bin", b"a\0b"),
                        ),
                    ),
            )
            .kv("success", "yes")
    }

    #[test]
    fn roundtrip() {
        let original = sample();
        let bytes = original.encode().expect("encode");
        let decoded = Section::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.get_str(&["conn", "version"]), Some("2"));
        assert_eq!(decoded.get_str(&["success"]), Some("yes"));
        assert_eq!(
            decoded.get_str(&["conn", "children", "net", "dpd_delay"]),
            Some("30s")
        );
        assert_eq!(
            decoded.get_str(&["conn", "children", ANY, "dpd_delay"]),
            Some("30s")
        );
        assert_eq!(
            decoded.get(&["conn", "children", "net", "bin"]),
            Some(&Item::KeyValue {
                key: "bin".into(),
                value: b"a\0b".to_vec()
            })
        );
        let addrs: Vec<&str> = decoded.get_str_list(&["conn", "remote_addrs"]).collect();
        assert_eq!(addrs, ["vpn.example.com", "10.0.0.1"]);
        assert!(decoded.get(&["conn", "nope"]).is_none());
        assert!(decoded.get_str(&["conn", "children"]).is_none());
        assert!(decoded.get(&["conn", "version", "x"]).is_none());
        let names: Vec<&str> = decoded
            .get_section(&["conn", "children"])
            .expect("children")
            .sections()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["net"]);
    }

    #[test]
    fn rejects_malformed_input() {
        let bytes = sample().encode().expect("encode");
        assert!(matches!(
            Section::decode(&bytes[..bytes.len() - 1]),
            Err(Error::Truncated)
        ));
        assert!(matches!(
            Section::decode(&bytes[..2]),
            Err(Error::Truncated)
        ));
        assert!(matches!(
            Section::decode(&[SECTION_END]),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            Section::decode(&[LIST_START, 1, b'l', LIST_START, 1, b'm']),
            Err(Error::Malformed("nested list"))
        ));
        assert!(matches!(
            Section::decode(&[LIST_ITEM, 0, 0]),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            Section::decode(&[SECTION_START, 1, b's']),
            Err(Error::Malformed("unterminated section"))
        ));
        assert!(matches!(
            Section::decode(&[9]),
            Err(Error::UnknownType {
                kind: "element",
                value: 9
            })
        ));
        let deep: Vec<u8> = [SECTION_START, 1, b's'].repeat(MAX_DEPTH + 1);
        assert!(matches!(
            Section::decode(&deep),
            Err(Error::Malformed("section nesting too deep"))
        ));
    }

    #[test]
    fn rejects_oversized_elements() {
        let long_name = "x".repeat(256);
        assert!(matches!(
            Section::new().kv(long_name, "v").encode(),
            Err(Error::NameLength(256))
        ));
        assert!(matches!(
            Section::new().kv("", "v").encode(),
            Err(Error::NameLength(0))
        ));
        assert!(matches!(
            Section::new().kv("k", vec![0u8; 65536]).encode(),
            Err(Error::ValueLength(65536))
        ));
    }
}
