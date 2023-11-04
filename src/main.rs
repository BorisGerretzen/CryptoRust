extern crate rabe_bn;
extern crate rand;

use std::net::IpAddr;
use std::str::FromStr;

use itertools::Itertools;
use rabe_bn::{Group, Gt, G1, G2};
use rand::Rng;
use warp;
use warp::Filter;

use crate::api::api_models::{
    AbeDecryptParams, AbeEncryptParams, AbeKeygenParams, AbeMediatorDecryptParams,
    AbePublicMasterKeypair,
};
use crate::errors::abe_error::AbeError;
use crate::models::AbeCipherText;
use crate::models::AbeSecretKeyPair;
use crate::parser::AccessTreeParser;

mod abe_attribute;
mod access_tree;
mod aes;
mod api;
mod crypto;
mod errors;
mod models;
mod parser;

fn setup(attributes: &String) -> Result<AbePublicMasterKeypair, AbeError> {
    let rng = &mut rand::thread_rng();
    let attributes = attributes
        .as_str()
        .split(",")
        .map(|s| s.to_string())
        .collect_vec();

    println!("Setup with attributes: {:?}", attributes);
    let (public, master) = crypto::setup(&attributes, G1::one(), G2::one(), rng);
    Ok(AbePublicMasterKeypair {
        public_key: public,
        master_key: master,
    })
}

fn keygen(params: &AbeKeygenParams) -> Result<AbeSecretKeyPair, AbeError> {
    println!("Generating keys for attributes: {:?}", params.attributes);

    let rng = &mut rand::thread_rng();
    let (client_key, mediator_key) = crypto::keygen(
        &params.attributes,
        &params.public_key,
        &params.master_key,
        rng,
    )?;
    Ok(AbeSecretKeyPair {
        client_key,
        mediator_key,
    })
}

fn encrypt(params: &AbeEncryptParams) -> Result<AbeCipherText, AbeError> {
    println!(
        "Encrypting message: {:?} with policy {:?}",
        params.message, params.access_policy
    );
    let rng = &mut rand::thread_rng();
    let access_policy = AccessTreeParser::new(&params.access_policy).parse()?;
    let bytes = params.message.as_bytes().to_vec();

    let cipher_text = crypto::encrypt(&rng.gen(), &bytes, &params.public_key, &access_policy, rng)?;
    Ok(cipher_text)
}

fn mediator_decrypt(params: &AbeMediatorDecryptParams) -> Result<Gt, AbeError> {
    println!(
        "Mediator decrypt for {} byte ciphertext",
        params.cipher_text.message.len()
    );
    let mediated_value = crypto::m_decrypt(&params.cipher_text, &params.secret_key)?;
    Ok(mediated_value)
}

fn decrypt(params: &AbeDecryptParams) -> Result<String, AbeError> {
    println!(
        "Decrypting {} byte ciphertext",
        params.cipher_text.message.len()
    );
    let decrypted = crypto::decrypt(
        &params.cipher_text,
        &params.secret_key,
        &params.mediated_value,
    )?;
    let as_string = String::from_utf8(decrypted.message).unwrap();
    Ok(as_string)
}

#[tokio::main]
async fn main() {
    let setup_route = warp::path!("setup" / String)
        .map(|attributes: String| process_result(|| setup(&attributes)));

    let setup_without_params_route = warp::path!("setup").map(|| {
        process_result(|| Err::<String, AbeError>(AbeError::new("No attributes provided")))
    });

    let keygen_route = warp::post()
        .and(warp::path!("keygen"))
        .and(warp::body::json())
        .map(|params: AbeKeygenParams| process_result(|| keygen(&params)));

    let encrypt_route = warp::post()
        .and(warp::path!("encrypt"))
        .and(warp::body::json())
        .map(|params: AbeEncryptParams| process_result(|| encrypt(&params)));

    let mediator_decrypt_route = warp::post()
        .and(warp::path!("mediator_decrypt"))
        .and(warp::body::json())
        .map(|params: AbeMediatorDecryptParams| process_result(|| mediator_decrypt(&params)));

    let decrypt_route = warp::post()
        .and(warp::path!("decrypt"))
        .and(warp::body::json())
        .map(|params: AbeDecryptParams| process_result(|| decrypt(&params)));

    let routes = setup_route
        .or(setup_without_params_route)
        .or(keygen_route)
        .or(encrypt_route)
        .or(mediator_decrypt_route)
        .or(decrypt_route);

    let addr = IpAddr::from_str("::0").unwrap();
    warp::serve(routes).bind((addr, 3030)).await;
}

fn handle_result<T>(result: Result<T, AbeError>) -> warp::reply::WithStatus<Box<dyn warp::Reply>>
where
    T: serde::Serialize,
{
    match result {
        Ok(data) => warp::reply::with_status(
            Box::new(warp::reply::json(&data)),
            warp::http::StatusCode::OK,
        ),
        Err(e) => {
            println!("Error: {:?}", e.message);
            warp::reply::with_status(
                Box::new(e.message),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

fn process_result<T, F>(func: F) -> warp::reply::WithStatus<Box<dyn warp::Reply>>
where
    F: Fn() -> Result<T, AbeError>,
    T: serde::Serialize,
{
    let result = func();
    handle_result(result)
}
