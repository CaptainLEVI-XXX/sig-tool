### Generate a ECDSA key 
```cargo run -- keygen --name my-ecdsa-key --scheme ecdsa```

### Generate a BLS key 
```cargo run -- keygen --name my-bls-key --scheme bls```

### List all keys
```cargo run -- list-keys```

### Sign a message with ECDSA
```cargo run -- sign --key my-ecdsa-key --message 'Hello, world!' --output ecdsa-signature.sig```

### Verify the ECDSA signature
```cargo run -- verify --key my-ecdsa-key --signature ecdsa-signature.sig --message 'Hello, world!'```

### Sign with BLS
```cargo run -- sign --key my-bls-key --message 'Hello, world!' --output bls-signature.sig```

### Verify BLS signature
```cargo run -- verify --key my-bls-key --signature bls-signature.sig --message 'Hello, world!'```