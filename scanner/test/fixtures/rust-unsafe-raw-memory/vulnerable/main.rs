fn reinterpret(bytes: [u8; 4]) -> u32 {
    unsafe { std::mem::transmute(bytes) }
}

fn read_at(buf: &[u8], i: usize) -> u8 {
    unsafe { *buf.get_unchecked(i) }
}
