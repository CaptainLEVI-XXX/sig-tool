use thiserror::Error;
use std::fmt::Debug;

#[derive(Debug,Error)]
pub enum SignatureError{
    
    #[error("Key Generation Error: {0}")]
    KeyGenration(String),
    
    #[error("Signing Error :{0}")]
    Signing(String),

    #[error("Verification Error: {0}")]
    Verififcation(String),

    #[error("Serialization Error: {0}")]
    Serialization(String),

    #[error("Deserialization Error: {0}")]
    Deserialization(String)
}

pub trait SignatureScheme : Send + Sync + Debug{
    
    type PrivateKey: Clone + Send + Sync;
    type PublicKey: Clone + Send + Sync;
    type Signature: Clone + Send + Sync;

    fn name() -> &'static String;

    fn generate_keypair()->Result<(Self::PrivateKey,Self::PublicKey),SignatureError>;

    fn sign(private_key: &Self::PrivateKey,message: &[u8] )-> Result<Self::Signature,SignatureError>;

    fn verify(public_key: &Self::PublicKey, message: &[u8])-> Result<bool,SignatureError>;

    //serialization

    fn serialize_private_key( private_key: &Self::PrivateKey)-> Result<Vec<u8>,SignatureError>;
    
    fn serialize_public_key( public_key: &Self::PublicKey)-> Result<Vec<u8>,SignatureError>;

    fn serialize_signature( signature: &Self::Signature)-> Result<Vec<u8>,SignatureError>;

    //deserialization

    fn deserialize_private_key(message: &[u8])->Result<Self::PrivateKey,SignatureError>;

    fn deserialize_public_key(message: &[u8])->Result<Self::PublicKey,SignatureError>;

    fn deserialize_public_key(message: &[u8])->Result<Self::Signature,SignatureError>;
}


