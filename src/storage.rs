use crate::crypto::{SignatureError,SignatureScheme};
use serde::{Serialize,Deserialize};
use std::fs::{self,File};
use std::io::Read;
use std::path::{Path,PathBuf};
use thiserror::Error;


#[derive(Error,Debug)]
pub enum StorageError{
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    
    #[error("Signature error: {0}")]
    Signature(#[from] SignatureError),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("Invalid key format")]
    InvalidFormat,

}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyMetadata{

    pub scheme:String,
    pub created_at:u64,
    pub name:String

}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyEntry{
    pub metadata:KeyMetadata,
    pub private_key:String,   //Hex-Encoded
    pub public_key:String     //Hex_Encoded
}

pub struct KeyStore {
    storage_dir: PathBuf,
}

impl KeyStore{
    pub fn new(storage_dir: impl AsRef<Path>)->Result<Self,StorageError>{
        let storage_dir = storage_dir.as_ref().to_path_buf();
        fs::create_dir_all(&storage_dir)?;
        Ok( Self {storage_dir} )
    }

    pub fn save_keypair<S:SignatureScheme>(
        &self,
        name:&str,
        private_key: &S::PrivateKey,
        public_key: &S::PublicKey
    )->Result<(),SignatureError>{

        let private_key = S::serialize_private_key(private_key)?;
        let public_key= S::serialize_public_key(public_key)?;
        let metadata = KeyMetadata {
            scheme: S::name().to_string(),
            created_at:std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
            name: name.to_string()
        };

        let entry = KeyEntry{
            metadata,
            private_key: hex::encode(&private_key),
            public_key:hex::encode(&public_key)
        };
        let path = self.key_path(name);
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, &entry)?;
       
        Ok(())

    }
    pub fn load_key_entry(&self,name: &str)->Result<KeyEntry,StorageError>{

        let path = self.key_path(name);
        let mut file = File::open(path).map_err(|_| StorageError::KeyNotFound(name.to_string()))?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        let entry: KeyEntry = serde_json::from_str(&contents)?;
        Ok(entry)
    }

    pub fn list_keys(&self) -> Result<Vec<KeyMetadata>, StorageError> {
        let mut results = Vec::new();
        
        for entry in fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && path.extension().unwrap_or_default() == "json" {
                if let Ok(file) = File::open(&path) {
                    if let Ok(entry) = serde_json::from_reader::<_, KeyEntry>(file) {
                        results.push(entry.metadata);
                    }
                }
            }
        }
        
        Ok(results)
    }
    
    fn key_path(&self, name: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.json", name))
    }
}

// Helper function to save a signature to file
pub fn save_signature(
    path: impl AsRef<Path>,
    scheme_name: &str,
    signature: &[u8],
) -> Result<(), StorageError> {
    #[derive(Serialize)]
    struct SignatureFile {
        scheme: String,
        signature: String,
        timestamp: u64,
    }
    
    let sig_file = SignatureFile {
        scheme: scheme_name.to_string(),
        signature: hex::encode(signature),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, &sig_file)?;
    
    Ok(())
}

// Helper function to load a signature from file
pub fn load_signature(path: impl AsRef<Path>) -> Result<(String, Vec<u8>), StorageError> {
    #[derive(Deserialize)]
    struct SignatureFile {
        scheme: String,
        signature: String,
    }
    
    let file = File::open(path)?;
    let sig_file: SignatureFile = serde_json::from_reader(file)?;
    
    let signature_bytes = hex::decode(&sig_file.signature)
        .map_err(|_| StorageError::InvalidFormat)?;
    
    Ok((sig_file.scheme, signature_bytes))
}

