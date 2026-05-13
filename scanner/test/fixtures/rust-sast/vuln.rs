use std::process::Command;
use sqlx::PgPool;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub async fn bad_sql(pool: &PgPool, user: &str) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", user))
        .execute(pool).await?;
    Ok(())
}

pub fn bad_cmd_shell(user: &str) {
    Command::new("sh").arg("-c").arg(user).output().unwrap();
}

pub fn bad_cmd_format(name: &str) {
    Command::new("ls").arg(format!("--filter={}", name)).output().unwrap();
}

pub fn bad_rng_seed() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0u8; 32])
}

pub fn bad_unsafe() {
    unsafe {
        let p: *const u8 = std::ptr::null();
        let _ = *p;
    }
}
