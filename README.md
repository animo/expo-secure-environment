# expo-secure-environment

Cryptographic operations using the devices Secure Environment (HSM,SE,etc.) locked behind biometric authentication

Currently Android API 30+ is supported and the MSV of iOS for Expo.

## Supported cryptographic algorithms

**key algorithm**: Secp256r1

**signature algorithm**: ECDSA with SHA256

## Create a key pair

```typescript
import { generateKeypair } from "@animo-id/expo-secure-environment";

const myId = "keypair-id";

// Make sure it is backed by biometrics
generateKeypair(myId, true);
```

## Get the public bytes by the id

Returns the compressed form of a P-256 public key (and not the DER-encoded SubjectPublicKeyInfo)

```typescript
import {
    generateKeypair,
    getPublicBytesForKeyId,
} from "@animo-id/expo-secure-environment";

const myId = "keypair-id";

// Make sure it is backed by biometrics
generateKeypair(myId, true);

const publicBytes: Uint8Array = getPublicBytesForKeyId(myId);
```

## Sign data

Returns the raw signature (and not a DER-Encoded ECDA-Sig-Value)

```typescript
import {
    generateKeypair,
    getPublicBytesForKeyId,
} from "@animo-id/expo-secure-environment";

const myId = "keypair-id";

// Make sure it is backed by biometrics
generateKeypair(myId, true);

// Make sure that when we sign we pass the third argument as true to indicate we would like to use biometrics
const signature = (myId, new Uint8Array(10).fill(7), true);
```
