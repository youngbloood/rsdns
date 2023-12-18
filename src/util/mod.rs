/// is_compressed judge the rrs weather use the compress.
/// if the third byte is zero and the first byte's first and second bit is 1, it represent compressed. or not
/// ref: https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
pub fn is_compressed(pointer: [u8; 2]) -> (usize, bool) {
    let mut off = [pointer[0], pointer[1]];
    off[0] &= 0b0011_1111;
    return (
        u16::from_be_bytes(off) as usize,
        pointer[0] & 0b1100_0000 == 0b1100_0000,
    );
}
