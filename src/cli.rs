use clap::{Parser, Subcommand};
use crate::crypto::{SignatureScheme, ECDSA, BLS};
use crate::storage::{KeyStore, StorageError, save_signature, load_signature};
use std::path::PathBuf;
use std::fs;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
    
    #[clap(long, default_value = "~/.sig-tool")]
    pub keystore: String,
}

#[derive(Subcommand)]
pub enum Commands {
    #[clap(name = "keygen")]
    KeyGen {
        /// Name to identify the key
        #[clap(short, long)]
        name: String,
        
        /// Signature scheme to use
        #[clap(short, long, default_value = "ecdsa", value_parser = ["ecdsa", "bls"])]
        scheme: String,
    },
    
    /// List all saved keys
    #[clap(name = "list-keys")]
    ListKeys,
    
    /// Sign a message
    #[clap(name = "sign")]
    Sign {
        /// Key to use for signing
        #[clap(short, long)]
        key: String,
        
        /// Message to sign (string)
        #[clap(short, long)]
        message: Option<String>,
        
        /// File containing message to sign
        #[clap(short, long)]
        file: Option<PathBuf>,
        
        /// Output file for the signature
        #[clap(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Verify a signature
    #[clap(name = "verify")]
    Verify {
        /// Key to use for verification
        #[clap(short, long)]
        key: String,
        
        /// Signature file to verify
        #[clap(short, long)]
        signature: PathBuf,
        
        /// Message that was signed (string)
        #[clap(short, long)]
        message: Option<String>,
        
        /// File containing message that was signed
        #[clap(short, long)]
        file: Option<PathBuf>,
    },
    
    /// Aggregate BLS signatures
    #[clap(name = "aggregate")]
    Aggregate {
        /// Signature files to aggregate (comma-separated)
        #[clap(short, long, use_value_delimiter = true, value_delimiter = ',')]
        signatures: Vec<PathBuf>,
        
        /// Output file for the aggregated signature
        #[clap(short, long)]
        output: PathBuf,
    },
    
    /// Verify an aggregated BLS signature
    #[clap(name = "verify-aggregate")]
    VerifyAggregate {
        /// Public keys to use for verification (comma-separated)
        #[clap(short, long, use_value_delimiter = true, value_delimiter = ',')]
        keys: Vec<String>,
        
        /// Aggregated signature file to verify
        #[clap(short, long)]
        signature: PathBuf,
        
        /// Message that was signed (string)
        #[clap(short, long)]
        message: Option<String>,
        
        /// File containing message that was signed
        #[clap(short, long)]
        file: Option<PathBuf>,
    },
}

pub fn run_cli(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Expand ~ to home directory if needed
    let keystore_path = if cli.keystore.starts_with("~/") {
        let home = dirs::home_dir().expect("Could not find home directory");
        home.join(&cli.keystore[2..])
    } else {
        PathBuf::from(cli.keystore)
    };
    
    let keystore = KeyStore::new(keystore_path)?;
    
    match cli.command {
        Commands::KeyGen { name, scheme } => {
            match scheme.as_str() {
                "ecdsa" => {
                    let (private_key, public_key) = ECDSA::generate_keypair()?;
                    keystore.save_keypair::<ECDSA>(&name, &private_key, &public_key)?;
                    println!("Generated ECDSA key pair: {}", name);
                }
                "bls" => {
                    let (private_key, public_key) = BLS::generate_keypair()?;
                    keystore.save_keypair::<BLS>(&name, &private_key, &public_key)?;
                    println!("Generated BLS key pair: {}", name);
                }
                _ => {
                    return Err(format!("Unsupported signature scheme: {}", scheme).into());
                }
            }
        }
        
        Commands::ListKeys => {
            let keys = keystore.list_keys()?;
            println!("Found {} keys:", keys.len());
            for key in keys {
                println!("- {} ({}, created: {})", key.name, key.scheme, key.created_at);
            }
        }
        
        Commands::Sign { key, message, file, output } => {
            let key_entry = keystore.load_key_entry(&key)?;
            let msg = get_message(message, file)?;
            
            match key_entry.metadata.scheme.as_str() {
                "ECDSA-secp256k1" => {
                    let private_key_bytes = hex::decode(&key_entry.private_key)
                        .map_err(|_| StorageError::InvalidFormat)?;
                    let private_key = ECDSA::deserialize_private_key(&private_key_bytes)?;
                    
                    let signature = ECDSA::sign(&private_key, &msg)?;
                    let sig_bytes = ECDSA::serialize_signature(&signature)?;
                    
                    if let Some(output_path) = output {
                        save_signature(&output_path, "ECDSA-secp256k1", &sig_bytes)?;
                        println!("Signature saved to {:?}", output_path);
                    } else {
                        println!("Signature: {}", hex::encode(&sig_bytes));
                    }
                }
                "BLS12-381-min-pk" => {
                    let private_key_bytes = hex::decode(&key_entry.private_key)
                        .map_err(|_| StorageError::InvalidFormat)?;
                    let private_key = BLS::deserialize_private_key(&private_key_bytes)?;
                    
                    let signature = BLS::sign(&private_key, &msg)?;
                    let sig_bytes = BLS::serialize_signature(&signature)?;
                    if let Some(output_path) = output {
                        save_signature(&output_path, "BLS12-381-min-pk", &sig_bytes)?;
                        println!("Signature saved to {:?}", output_path);
                    } else {
                        println!("Signature: {}", hex::encode(&sig_bytes));
                    }
                }
                _ => {
                    return Err(format!("Unsupported signature scheme: {}", key_entry.metadata.scheme).into());
                }
            }
        }
        
        Commands::Verify { key, signature, message, file } => {
            let key_entry = keystore.load_key_entry(&key)?;
            let msg = get_message(message, file)?;
            let (scheme, sig_bytes) = load_signature(signature)?;
            
            if scheme != key_entry.metadata.scheme {
                return Err(format!("Signature scheme mismatch: {} vs {}", 
                                  scheme, key_entry.metadata.scheme).into());
            }
            
            match scheme.as_str() {
                "ECDSA-secp256k1" => {
                    let public_key_bytes = hex::decode(&key_entry.public_key)
                        .map_err(|_| StorageError::InvalidFormat)?;
                    let public_key = ECDSA::deserialize_public_key(&public_key_bytes)?;
                    
                    let signature = ECDSA::deserialize_signature(&sig_bytes)?;
                    let is_valid = ECDSA::verify(&public_key, &msg, &signature)?;
                    
                    println!("Signature verification: {}", if is_valid { "VALID ✓" } else { "INVALID ✗" });
                }
                "BLS12-381-min-pk" => {
                    let public_key_bytes = hex::decode(&key_entry.public_key)
                        .map_err(|_| StorageError::InvalidFormat)?;
                    let public_key = BLS::deserialize_public_key(&public_key_bytes)?;
                    
                    let signature = BLS::deserialize_signature(&sig_bytes)?;
                    let is_valid = BLS::verify(&public_key, &msg, &signature)?;
                    
                    println!("Signature verification: {}", if is_valid { "VALID ✓" } else { "INVALID ✗" });
                }
                _ => {
                    return Err(format!("Unsupported signature scheme: {}", scheme).into());
                }
            }
        }
        
        Commands::Aggregate { signatures, output } => {
            let mut bls_signatures = Vec::new();
            
            for sig_path in signatures {
                let (scheme, sig_bytes) = load_signature(sig_path)?;
                
                if scheme != "BLS12-381-min-pk" {
                    return Err(format!("Can only aggregate BLS signatures, found: {}", scheme).into());
                }
                
                let signature = BLS::deserialize_signature(&sig_bytes)?;
                bls_signatures.push(signature);
            }
            
            use crate::crypto::bls::BLSSignature;
            let aggregated = BLSSignature::aggregate(&bls_signatures)?;
            
            let agg_bytes = BLS::serialize_signature(&aggregated)?;
            save_signature(&output, "BLS12-381-min-pk-aggregated", &agg_bytes)?;
            println!("Aggregated signature saved to {:?}", output);
        }
        
        Commands::VerifyAggregate { keys, signature, message, file } => {
            let _msg = get_message(message, file)?;
            let (scheme, _sig_bytes) = load_signature(signature)?;
            
            if !scheme.starts_with("BLS12-381-min-pk") {
                return Err(format!("Expected BLS signature, found: {}", scheme).into());
            }
            
            let mut public_keys = Vec::new();
            
            for key_name in keys {
                let key_entry = keystore.load_key_entry(&key_name)?;
                
                if key_entry.metadata.scheme != "BLS12-381-min-pk" {
                    return Err(format!("Key {} is not a BLS key", key_name).into());
                }
                
                let pk_bytes = hex::decode(&key_entry.public_key)
                    .map_err(|_| StorageError::InvalidFormat)?;
                let public_key = BLS::deserialize_public_key(&pk_bytes)?;
                
                public_keys.push(public_key);
            }
            
            // For aggregated signature verification, we'd normally need to implement a specialized function
            // that verifies the aggregated signature against all public keys and messages
            // This is a simplified version that assumes all signatures were made on the same message
            
            println!("Aggregated signature verification not fully implemented in this example.");
            println!("For a complete implementation, you'd need a specialized verification function.");
        }
    }
    
    Ok(())
}

// Helper to get message from either a string or a file
fn get_message(message_str: Option<String>, message_file: Option<PathBuf>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match (message_str, message_file) {
        (Some(msg), None) => Ok(msg.into_bytes()),
        (None, Some(file)) => Ok(fs::read(file)?),
        (None, None) => Err("Either message or file must be specified".into()),
        (Some(_), Some(_)) => Err("Cannot specify both message and file".into()),
    }
}