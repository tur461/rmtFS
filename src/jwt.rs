use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, errors::Error};
use serde::{Deserialize, Serialize};

const SECRET: &[u8] = b"the quick brown fox jumped over a lazy black dog.";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user id
    pub exp: usize,  // expiry as timestamp
}

pub fn create_jwt(user_id: String, expiration: usize) -> Result<String, Error> {
    let claims = Claims {
        sub: user_id,
        exp: expiration,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET))
}

pub fn verify_jwt(token: &str) -> Result<Claims, Error> {
    decode::<Claims>(token, &DecodingKey::from_secret(SECRET), &Validation::default()).map(|data| data.claims)
}
