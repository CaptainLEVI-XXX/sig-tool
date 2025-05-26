# Crypto CLI Commands

## Generate Keys

### Generate a ECDSA key 
```bash
cargo run -- keygen --name my-ecdsa-key --scheme ecdsa
```

### Generate a BLS key 
```bash
cargo run -- keygen --name my-bls-key --scheme bls
```

## List Keys

### List all keys
```bash
cargo run -- list-keys
```

## Signing Messages

### Sign a message with ECDSA
```bash
cargo run -- sign --key my-ecdsa-key --message 'Hello, world!' --output ecdsa-signature.sig
```

### Sign with BLS
```bash
cargo run -- sign --key my-bls-key --message 'Hello, world!' --output bls-signature.sig
```

## Verifying Signatures

### Verify the ECDSA signature
```bash
cargo run -- verify --key my-ecdsa-key --signature ecdsa-signature.sig --message 'Hello, world!'
```

### Verify BLS signature
```bash
cargo run -- verify --key my-bls-key --signature bls-signature.sig --message 'Hello, world!'
```