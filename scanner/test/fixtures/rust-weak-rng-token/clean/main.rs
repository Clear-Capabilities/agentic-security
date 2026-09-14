use rand::rngs::OsRng;
use rand::RngCore;

fn issue_session_token() -> [u8; 32] {
    let mut session_token = [0u8; 32];
    OsRng.fill_bytes(&mut session_token);
    session_token
}
