<p align="center">
  <picture>
   <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-light-no-text_ok9auy.svg">
   <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-dark-no-text_fqqdq9.svg">
   <img alt="Animo Logo" height="200px" />
  </picture>
</p>

<h1 align="center" ><b>Expo - Secure Environment</b></h1>

<h4 align="center">Powered by &nbsp; 
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-light-text_cma2yo.svg">
    <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-dark-text_uccvqa.svg">
    <img alt="Animo Logo" height="12px" />
  </picture>
</h4><br>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
  <a href="https://www.npmjs.com/package/@animo-id/expo-secure-environment">
    <img src="https://img.shields.io/npm/v/@animo-id/expo-secure-environment" />
  </a>
  <a
    href="https://raw.githubusercontent.com/animo/expo-secure-environment/main/LICENSE"
    ><img
      alt="License"
      src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"
  /></a>
</p>

<p align="center">
  <a href="#getting-started">Getting Started</a> 
  &nbsp;|&nbsp;
  <a href="#usage">Usage</a> 
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a> 
  &nbsp;|&nbsp;
  <a href="#contributing">License</a> 
</p>

---

An [Expo Module](https://docs.expo.dev/modules/overview/) with support for cryptographic operations using the device's Secure Environment (HSM, SE, etc.) locked behing biometric authentication.

Currently supports Android API 30+ and the minimum supported version of iOS for Expo.


## Getting Started

First, install the module using your package manager.

```sh
npm install @animo-id/expo-secure-environment
```

Then prebuild the application so the Expo Module wrapper can be added as native dependency:

```sh
npx expo prebuild
```

You now have the Secure Environment module installed and configured.

## Usage

You can now import `@animo-id/expo-secure-environment` in your application.

### Supported cryptographic algorithms

**Key algorithm**: Secp256r1

**Signature algorithm**: ECDSA with SHA256

### Create a key pair

```typescript
import { generateKeypair } from "@animo-id/expo-secure-environment";

const myId = "keypair-id";

// Make sure it is backed by biometrics
generateKeypair(myId, true);
```

### Get the public bytes by the id

Returns the compressed form of a P-256 public key (and not the DER-encoded SubjectPublicKeyInfo):

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

### Sign data

Returns the raw signature (and not a DER-Encoded ECDA-Sig-Value):

```typescript
import {
    generateKeypair,
    sign
} from "@animo-id/expo-secure-environment";

const myId = "keypair-id";

// Make sure it is backed by biometrics
generateKeypair(myId, true);

// Make sure that when we sign we pass the third argument as true to indicate we would like to use biometrics
const signature = sign(myId, new Uint8Array(10).fill(7), true);
```

## Contributing

Is there something you'd like to fix or add? Great, we love community contributions! To get involved, please follow our [contribution guidelines](https://github.com/animo/.github/blob/main/CONTRIBUTING.md).

## License

This repository is licensed under the [Apache 2.0](./LICENSE) license.
