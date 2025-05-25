use crate::crypto::scheme::{SignatureScheme, SignatureError};
use blst::{min_pk::*, BLST_ERROR};
use rand::{rngs::OsRng, RngCore};
use std::convert::TryFrom;

#[derive(Debug)]
pub struct BLS;

// Wrapper types for BLS keys and signatures
#[derive(Clone, Debug)]
pub struct BLSPrivateKey(SecretKey);

#[derive(Clone, Debug)]
pub struct BLSPublicKey(PublicKey);

#[derive(Clone, Debug)]
pub struct BLSSignature(Signature);

// Implement aggregation for BLS signatures (not part of the trait)
impl BLSSignature {
    pub fn aggregate(signatures: &[BLSSignature]) -> Result<Self, SignatureError> {
        let sigs: Vec<&Signature> = signatures.iter().map(|s| &s.0).collect();
        
        match Signature::aggregate(&sigs[..], false) {
            Ok(agg_sig) => Ok(BLSSignature(agg_sig)),
            Err(_) => Err(SignatureError::Signing("Failed to aggregate signatures".into())),
        }
    }
}

impl SignatureScheme for BLS {
    type PrivateKey = BLSPrivateKey;
    type PublicKey = BLSPublicKey;
    type Signature = BLSSignature;
    
    fn name() -> &'static str {
        "BLS12-381-min-pk"
    }
    
    fn generate_keypair() -> Result<(Self::PrivateKey, Self::PublicKey), SignatureError> {
        let mut ikm = [0u8; 32];
        OsRng.fill_bytes(&mut ikm);
        
        let sk = match SecretKey::key_gen(&ikm, &[]) {
            Ok(key) => key,
            Err(_) => return Err(SignatureError::KeyGeneration("Failed to generate BLS key".into())),
        };
        
        let pk = sk.sk_to_pk();
        
        Ok((BLSPrivateKey(sk), BLSPublicKey(pk)))
    }
    
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Self::Signature, SignatureError> {
        let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
        let sig = private_key.0.sign(message, dst, &[]);
        
        Ok(BLSSignature(sig))
    }
    
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<bool, SignatureError> {
        let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
        
        let result = signature.0.verify(true, message, dst, &[], &public_key.0, false);
        
        match result {
            BLST_ERROR::BLST_SUCCESS => Ok(true),
            _ => Ok(false),
        }
    }
    
    // Serialization methods for BLS keys and signatures
    fn serialize_private_key(private_key: &Self::PrivateKey) -> Result<Vec<u8>, SignatureError> {
        let mut bytes = Vec::new();
        private_key.0.serialize(&mut bytes);
        Ok(bytes)
    }
    
    fn deserialize_private_key(bytes: &[u8]) -> Result<Self::PrivateKey, SignatureError> {
        match SecretKey::deserialize(bytes) {
            Ok(sk) => Ok(BLSPrivateKey(sk)),
            Err(_) => Err(SignatureError::Deserialization("Failed to deserialize BLS private key".into())),
        }
    }
    
    fn serialize_public_key(public_key: &Self::PublicKey) -> Result<Vec<u8>, SignatureError> {
        let mut bytes = Vec::new();
        public_key.0.serialize(&mut bytes);
        Ok(bytes)
    }
    
    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, SignatureError> {
        match PublicKey::deserialize(bytes) {
            Ok(pk) => Ok(BLSPublicKey(pk)),
            Err(_) => Err(SignatureError::Deserialization("Failed to deserialize BLS public key".into())),
        }
    }
    
    fn serialize_signature(signature: &Self::Signature) -> Result<Vec<u8>, SignatureError> {
        let mut bytes = Vec::new();
        signature.0.serialize(&mut bytes);
        Ok(bytes)
    }
    
    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature, SignatureError> {
        match Signature::deserialize(bytes) {
            Ok(sig) => Ok(BLSSignature(sig)),
            Err(_) => Err(SignatureError::Deserialization("Failed to deserialize BLS signature".into())),
        }
    }
}