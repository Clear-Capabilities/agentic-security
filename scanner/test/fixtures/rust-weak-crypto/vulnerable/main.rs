use md5;
use sha1::Sha1;

fn fingerprint(data: &[u8]) -> [u8; 16] {
    md5::compute(data).0
}

fn legacy_hash(data: &[u8]) {
    let mut hasher = Sha1::new();
}
