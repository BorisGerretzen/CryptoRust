use rabe_bn::Gt;

use crate::models::{AbeCipherText, AbeClientKey, AbeMasterKey, AbeMediatorKey, AbePublicKey};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AbePublicMasterKeypair {
    pub public_key: AbePublicKey,
    pub master_key: AbeMasterKey,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AbeKeygenParams {
    pub public_key: AbePublicKey,
    pub master_key: AbeMasterKey,
    pub attributes: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AbeEncryptParams {
    pub message: String,
    pub public_key: AbePublicKey,
    pub access_policy: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AbeMediatorDecryptParams {
    pub cipher_text: AbeCipherText,
    pub secret_key: AbeMediatorKey,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AbeDecryptParams {
    pub cipher_text: AbeCipherText,
    pub secret_key: AbeClientKey,
    pub mediated_value: Gt,
}
