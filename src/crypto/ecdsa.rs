use crate::crypto::scheme::{SignatureError,SignatureScheme};
use rand::rngs::OsRng;
use k256::ecdsa::{SigningKey,VerifyingKey, Signature as ECDSASignature};
use std::convert::TryFrom;

#[derive(Debug)]
pub struct ECDSA;

impl SignatureScheme for ECDSA{

    type PrivateKey = SigningKey;
    type PublicKey =  VerifyingKey;
    type Signature = ECDSASignature;

    fn name()-> &'static str{
        "ECDSA-secp256k1"
    }

    fn generate_keypair()->Result<(Self::PrivateKey,Self::PublicKey),SignatureError>{
        
        let private_key = SigningKey::random(&mut OsRng);

        let public_key = VerifyingKey::from(&private_key);

        Ok((private_key,public_key)) 
    }

    fn sign(private_key: &Self::PrivateKey,message: &[u8] )-> Result<Self::Signature,SignatureError>{

        use k256::ecdsa::signature::Signer;

        let signature = private_key.sign(message);
        Ok(signature)
    }

    fn verify(public_key: &Self::PublicKey, message: &[u8],signature:&Self::Signature)-> Result<bool,SignatureError>{
        use k256::ecdsa::signature::Verifier;

        match public_key.verify(message,signature){
            Ok(())=> Ok(true),
            Err(_)=>Ok(false)
        } 
    }

    fn serialize_private_key( private_key: &Self::PrivateKey)-> Result<Vec<u8>,SignatureError>{
        Ok(private_key.to_bytes().to_vec())
    }

    fn serialize_public_key( public_key: &Self::PublicKey)-> Result<Vec<u8>,SignatureError>{
        Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
    }

    fn serialize_signature( signature: &Self::Signature)-> Result<Vec<u8>,SignatureError>{
        use k256::ecdsa::signature::SignatureEncoding;
        Ok(signature.to_der().to_vec())
    }

    //deserialization

    fn deserialize_private_key(bytes: &[u8])->Result<Self::PrivateKey,SignatureError>{
        // SigningKey::from_bytes(bytes)
        //     .map_err(|e| SignatureError::Deserialization(e.to_string()))
                // Convert slice to fixed-size array
                if bytes.len() != 32 {
                    return Err(SignatureError::Deserialization(
                        format!("Invalid private key length: expected 32 bytes, got {}", bytes.len())
                    ));
                }
                
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(bytes);
                
                SigningKey::from_bytes(&key_bytes.into())
                    .map_err(|e| SignatureError::Deserialization(e.to_string()))
    }

    fn deserialize_public_key(bytes: &[u8])->Result<Self::PublicKey,SignatureError>{
        VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|e| SignatureError::Deserialization(e.to_string()))
    }

    fn deserialize_signature(bytes: &[u8])->Result<Self::Signature,SignatureError> {
        ECDSASignature::try_from(bytes)
            .map_err(|e| SignatureError::Deserialization(e.to_string()))
    }

}