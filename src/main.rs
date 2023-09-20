extern crate rabe_bn;
extern crate rand;

use std::fs;
use std::fs::{read, read_to_string};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use itertools::Itertools;
use rabe_bn::{Group, Gt, G1, G2};
use rand::Rng;
use serde::Deserialize;

use crate::errors::abe_error::AbeError;
use crate::models::{AbeCipherText, AbeMasterKey, AbePublicKey, AbeSecretKey};
use crate::parser::AccessTreeParser;

mod abe_attribute;
mod access_tree;
mod aes;
mod crypto;
mod errors;
mod models;
mod parser;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone)]
enum Commands {
    Setup(SetupArgs),
    Keygen(KeygenArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

#[derive(Args, Clone)]
struct SetupArgs {
    /// OUT | Where to save public key
    public_key: PathBuf,

    /// OUT | Where to save master key
    master_key: PathBuf,

    /// Attribute set of the system
    #[arg(required = true)]
    attributes: Vec<String>,
}

#[derive(Args, Clone)]
struct KeygenArgs {
    /// IN | Path to public key
    public_key: PathBuf,

    /// IN | Path to master key
    master_key: PathBuf,

    /// OUT | Where to save secret key
    secret_key: PathBuf,

    /// Attribute set of the key
    #[arg(required = true)]
    attributes: Vec<String>,
}

#[derive(Args, Clone)]
struct EncryptArgs {
    /// Access policy, e.g. "(A & B) | (C & D)"
    policy: String,

    /// IN | Path to public key
    public_key: PathBuf,

    /// IN | Path to input file
    input: PathBuf,

    /// OUT | Where to save encrypted data
    output: PathBuf,
}

#[derive(Args, Clone)]
struct DecryptArgs {
    /// IN | Path to secret key
    private_key: PathBuf,

    /// IN | Path to encrypted data
    input: PathBuf,

    /// OUT | Where to save decrypted data
    output: PathBuf,
}
fn main() {
    let cli = Cli::parse();
    let rng = &mut rand::thread_rng();

    let result = match cli.command {
        Commands::Setup(args) => do_setup(&args, rng),
        Commands::Keygen(args) => do_keygen(&args, rng),
        Commands::Encrypt(args) => do_encrypt(&args, rng),
        Commands::Decrypt(args) => do_decrypt(&args),
    };
    match result {
        Ok(_) => println!("Done"),
        Err(e) => println!("Error: {:?}", e.to_string()),
    }
}

// constrain output types to have the `Deserialize` trait
fn deserialize<'a, T>(data: &'a str) -> Option<T>
where
    T: Deserialize<'a>,
{
    match serde_json::from_str::<T>(data) {
        Ok(value) => Some(value),
        Err(_) => None,
    }
}

fn do_setup<R: Rng + ?Sized>(args: &SetupArgs, rng: &mut R) -> Result<(), AbeError> {
    if args.attributes.len() == 0 {
        return Err(AbeError::new("No attributes given"));
    }

    let (public, master) = crypto::setup(&args.attributes, G1::one(), G2::one(), rng);

    let serialized_master_key = serde_json::to_string(&master).map_err(|e| {
        AbeError::new(format!("Could not serialize master key: {:?}", e.to_string()).as_str())
    })?;
    let serialized_public_key = serde_json::to_string(&public).map_err(|e| {
        AbeError::new(format!("Could not serialize public key: {:?}", e.to_string()).as_str())
    })?;

    fs::write(&args.master_key, serialized_master_key).map_err(|e| {
        AbeError::new(format!("Could not write master key: {:?}", e.to_string()).as_str())
    })?;
    fs::write(&args.public_key, serialized_public_key).map_err(|e| {
        AbeError::new(format!("Could not write public key: {:?}", e.to_string()).as_str())
    })?;
    Ok(())
}

fn do_keygen<R: Rng + ?Sized>(args: &KeygenArgs, rng: &mut R) -> Result<(), AbeError> {
    if args.attributes.len() == 0 {
        return Err(AbeError::new("No attributes given"));
    }

    let public_key = read_to_string(&args.public_key).map_err(|e| {
        AbeError::new(format!("Could not read public key: {:?}", e.to_string()).as_str())
    })?;
    let master_key = read_to_string(&args.master_key).map_err(|e| {
        AbeError::new(format!("Could not read master key: {:?}", e.to_string()).as_str())
    })?;

    let public_key = deserialize::<AbePublicKey>(&public_key)
        .ok_or(AbeError::new("Could not deserialize public key"))?;
    let master_key = deserialize::<AbeMasterKey>(&master_key)
        .ok_or(AbeError::new("Could not deserialize master key"))?;

    // check if attributes exist in public key
    let public_key_attributes = public_key.big_t.iter().map(|(attr, _)| attr).collect_vec();
    let not_found = args
        .attributes
        .iter()
        .filter(|attr| !public_key_attributes.contains(attr))
        .collect_vec();
    if not_found.len() > 0 {
        return Err(AbeError::new(
            format!("Attributes not found in public key: {:?}", not_found).as_str(),
        ));
    }

    let secret_key =
        crypto::keygen(&args.attributes, &public_key, &master_key, rng).map_err(|e| {
            AbeError::new(format!("Could not serialize secret key: {:?}", e.to_string()).as_str())
        })?;

    let serialized_secret_key = serde_json::to_string(&secret_key).map_err(|e| {
        AbeError::new(format!("Could not serialize secret key: {:?}", e.to_string()).as_str())
    })?;
    fs::write(&args.secret_key, serialized_secret_key).map_err(|e| {
        AbeError::new(format!("Could not write secret key: {:?}", e.to_string()).as_str())
    })?;

    Ok(())
}

fn do_encrypt<R: Rng + ?Sized>(args: &EncryptArgs, rng: &mut R) -> Result<(), AbeError> {
    let public_key = read_to_string(&args.public_key).map_err(|e| {
        AbeError::new(format!("Could not read public key: {:?}", e.to_string()).as_str())
    })?;
    let public_key = deserialize::<AbePublicKey>(&public_key)
        .ok_or(AbeError::new("Could not deserialize public key"))?;

    let access_tree = AccessTreeParser::new(args.policy.as_str())
        .parse()
        .map_err(|e| {
            AbeError::new(format!("Could not parse access tree: {:?}", e.to_string()).as_str())
        })?;

    let input = read(&args.input).map_err(|e| {
        AbeError::new(format!("Could not read input file: {:?}", e.to_string()).as_str())
    })?;

    let secret: Gt = rng.gen();
    let ciphertext = crypto::encrypt(&secret, &input, &public_key, &access_tree, rng)
        .map_err(|e| AbeError::new(format!("Could not encrypt: {:?}", e.to_string()).as_str()))?;

    let serialized_ciphertext = serde_json::to_string(&ciphertext).map_err(|e| {
        AbeError::new(format!("Could not serialize cipher text: {:?}", e.to_string()).as_str())
    })?;
    fs::write(&args.output, serialized_ciphertext).map_err(|e| {
        AbeError::new(format!("Could not write output file: {:?}", e.to_string()).as_str())
    })?;

    Ok(())
}

fn do_decrypt(args: &DecryptArgs) -> Result<(), AbeError> {
    let cipher_text = read_to_string(&args.input).map_err(|e| {
        AbeError::new(format!("Could not read cipher text: {:?}", e.to_string()).as_str())
    })?;
    let cipher_text = deserialize::<AbeCipherText>(&cipher_text)
        .ok_or(AbeError::new("Could not deserialize cipher text"))?;

    let secret_key = read_to_string(&args.private_key).map_err(|e| {
        AbeError::new(format!("Could not read secret key: {:?}", e.to_string()).as_str())
    })?;
    let secret_key =
        deserialize::<AbeSecretKey>(&secret_key).expect("Could not deserialize secret key");

    let decrypted = crypto::decrypt(&cipher_text, &secret_key)
        .map_err(|e| AbeError::new(format!("Could not decrypt: {:?}", e.to_string()).as_str()))?;
    fs::write(&args.output, decrypted.message).map_err(|e| {
        AbeError::new(format!("Could not write output file: {:?}", e.to_string()).as_str())
    })?;

    Ok(())
}
