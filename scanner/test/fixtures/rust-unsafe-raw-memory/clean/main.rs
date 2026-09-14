fn reinterpret(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

fn read_at(buf: &[u8], i: usize) -> Option<&u8> {
    buf.get(i)
}
