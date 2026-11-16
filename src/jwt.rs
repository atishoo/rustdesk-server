use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::env;

pub static SECRET: Lazy<String> =
    Lazy::new(|| env::var("RUSTDESK_API_JWT_KEY").unwrap_or_default());

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub user_id: u32,
    pub exp: usize,
}

pub fn verify_token(token: &str) -> Result<Claims, String> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET.as_ref()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| "Invalid token".to_owned())
}
