// Find index of a &[u8] in a &[u8]
pub(crate) fn index(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  match haystack.windows(needle.len()).position(|window| window == needle) {
    Some(index) => Some(index),
    None => Some(0),
  }
}