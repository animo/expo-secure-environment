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

Requires Expo SDK 53 or newer. Supports Android 11 (API 30) and newer, and iOS 16.4 and newer.

Apps that support older Android versions can still include the library. There `isSecureEnvironmentSupported` and `isUserAuthenticationAvailable` return `false`, and the other functions throw a `SecureEnvironmentNotSupportedError`.

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

### Check support

Keys are stored in the Secure Enclave on iOS, and in StrongBox, the Trusted Execution Environment (TEE) or software on Android. Check that the device has one before you generate keys:

```typescript
import { isSecureEnvironmentSupported } from "@animo-id/expo-secure-environment";

isSecureEnvironmentSupported(); // Secure Enclave on iOS, StrongBox on Android
isSecureEnvironmentSupported({ minimumKeyStorage: "trustedEnvironment" }); // TEE or StrongBox on Android
```

Keys that require user authentication also need enrolled biometrics or a device passcode. Check this before a flow that creates such a key, for example to ask the user to set up Face ID first:

```typescript
import { isUserAuthenticationAvailable } from "@animo-id/expo-secure-environment";

isUserAuthenticationAvailable(); // biometrics enrolled
isUserAuthenticationAvailable({ methods: ["biometric", "deviceCredential"] }); // biometrics or a device passcode
```

On iOS this is also `false` while biometrics are locked after too many failed attempts.

### Create a key pair

By default signing with the key requires biometric authentication every time:

```typescript
import { generateKeypair } from "@animo-id/expo-secure-environment";

await generateKeypair("my-key");
```

Configure the key with the options:

```typescript
await generateKeypair("my-key", {
  userAuthentication: {
    methods: ["biometric", "deviceCredential"],
    invalidateOnBiometricChange: true,
  },
  minimumKeyStorage: "trustedEnvironment",
});
```

| Option | Default | Description |
| --- | --- | --- |
| `userAuthentication` | | The user authentication needed to sign, or `false` for none. |
| `userAuthentication.methods` | `['biometric']` | `biometric` (Face ID, Touch ID, Android Class 3 biometrics) and/or `deviceCredential` (device passcode, PIN, pattern or password). |
| `userAuthentication.invalidateOnBiometricChange` | `true` | Whether the key becomes unusable when biometrics are added or removed on the device. Only applies when `methods` is `['biometric']`. |
| `userAuthentication.validitySeconds` | `0` | Android only. How long the key can be used after the user authenticated. `0` requires authentication for every signature. |
| `minimumKeyStorage` | `'strongBox'` | Android only. The least secure storage the key may be stored in, see [Key storage on Android](#key-storage-on-android). iOS always uses the Secure Enclave. |
| `preferStrongBox` | `true` | Android only. Whether to store the key in StrongBox when the device has it, also when `minimumKeyStorage` doesn't require it. |
| `attestationChallenge` | | Android only. Creates a key attestation that includes this challenge, see [Key attestation](#key-attestation-android). |

#### Key storage on Android

Android stores keys in StrongBox when you ask for it. All other keys go to the default key storage of the device: the TEE, or software on devices without a TEE, such as emulators. Apps can't choose between the TEE and software, so `minimumKeyStorage` sets the least secure storage you accept:

| `minimumKeyStorage` | Where the key is stored | Fails when |
| --- | --- | --- |
| `strongBox` | StrongBox, a separate secure element. | The device has no StrongBox. |
| `trustedEnvironment` | StrongBox when the device has it, otherwise the default key storage, which must be the TEE. | The device has no TEE. |
| `software` | StrongBox when the device has it, otherwise the default key storage: the TEE, or software. | Never. |

When StrongBox can't store the key, it goes to the default key storage instead. StrongBox is slower than the TEE and can run fewer operations at the same time. To always use the default key storage, for example when you generate many keys at once, set `preferStrongBox: false`.

A key in software can't be read by your app, but Android itself can read it, so it's not protected against a compromised (e.g. rooted) device.

`getKeyStorage` returns where a key ended up:

```typescript
import { getKeyStorage } from "@animo-id/expo-secure-environment";

await getKeyStorage("my-key"); // 'strongBox', 'trustedEnvironment', 'software' or 'secureHardware'
```

Android 11 doesn't say whether a key in secure hardware is in StrongBox or the TEE, so there it returns `secureHardware` for both. A verifier can also read the storage from the [key attestation](#key-attestation-android).

### Get the public key

Returns the compressed form of the P-256 public key (and not the DER-encoded SubjectPublicKeyInfo):

```typescript
import { getPublicBytesForKeyId } from "@animo-id/expo-secure-environment";

const publicKey: Uint8Array = await getPublicBytesForKeyId("my-key");
```

### Sign data

Returns the raw signature (and not a DER-Encoded ECDSA-Sig-Value). When the key requires user authentication, the user is asked to authenticate first:

```typescript
import { sign } from "@animo-id/expo-secure-environment";

const signature = await sign("my-key", message, {
  prompt: { title: "Sign in to Example", cancel: "Cancel" },
});
```

Wait for a signature that shows a prompt before you start the next one. iOS shows one prompt at a time, so a second prompt cancels the first, which then throws a `UserAuthenticationCanceledError`. Android shows the prompts one after the other.

### Sign multiple times

To create several signatures at once, for example to present multiple credentials, use `withUserAuthentication`. On iOS the user authenticates once, at the first signature with a key that requires it, and the next signatures reuse that authentication. Keys that don't require user authentication never ask. On Android it signs like `sign`: keep the default `validitySeconds` of `0` and show one prompt per signature, with a title that says what the user signs. The secure hardware then allows one signature per authentication, so no other code in the app can sign without asking the user.

```typescript
import { withUserAuthentication } from "@animo-id/expo-secure-environment";

async function signCredentials(credentials: { keyId: string; name: string }[], message: Uint8Array) {
  return withUserAuthentication(
    async ({ sign }) => {
      const signatures = [];
      for (const [index, { keyId, name }] of credentials.entries()) {
        // The prompt of each signature on Android
        const prompt = { title: `Share ${name}`, subtitle: `${index + 1} of ${credentials.length}` };
        signatures.push(await sign(keyId, message, { prompt }));
      }
      return signatures;
    },
    // The prompt of the one authentication on iOS
    { prompt: { title: `Share ${credentials.length} credentials` } }
  );
}
```

Only the `sign` of `withUserAuthentication` reuses the authentication, and only until the callback returns. After that it throws. Other `sign` calls in the app still ask the user, also while the callback runs, so pass the `sign` on to code that should share the authentication. It signs one message at a time, so a second prompt can't cancel the first. On iOS the next keys reuse the authentication when they accept the method the user authenticated with: a key that only accepts the passcode asks again after biometrics.

On Android, keys generated with `validitySeconds` above `0` ask once and then sign without a prompt until the validity ends. A validity is less secure. Until it ends, any code in the app can sign without a prompt, not only the `sign` of `withUserAuthentication`, and unlocking the device with one of the key's `methods` also starts it. If you use one, keep it just long enough for the signatures you create at once.

### Key attestation (Android)

On Android a key can be created with a key attestation: a certificate chain from the device's secure hardware that proves the key was generated there, describes how the key is protected, and includes the challenge. Pass the challenge when creating the key, then get the certificate chain (base64 encoded DER certificates, leaf first):

```typescript
import {
  generateKeypair,
  getAttestationCertificateChain,
} from "@animo-id/expo-secure-environment";

await generateKeypair("my-key", { attestationChallenge: challenge });
const certificateChain: string[] = await getAttestationCertificateChain("my-key");
```

iOS has no key attestation for Secure Enclave keys. There the challenge is ignored and `getAttestationCertificateChain` throws.

The key attestations in OpenID4VCI state the `key_storage` and `user_authentication` levels of a key (attack potential resistance, ISO 18045). Your wallet determines those levels from how it configures the keys with `userAuthentication`, and from where `getKeyStorage` says a key is stored. This library doesn't assign levels.

### Errors

All errors extend `SecureEnvironmentError`, which has the `keyId` and the native error `code`. Errors with a specific cause have their own class:

| Error | Thrown when |
| --- | --- |
| `SecureEnvironmentNotSupportedError` | The device has no Secure Enclave, or not the requested `minimumKeyStorage`, or runs Android 10 or older. |
| `KeyNotFoundError` | No key with this id exists. |
| `KeyAlreadyExistsError` | A key with this id already exists. |
| `KeyInvalidatedError` | Android only. The key was permanently invalidated, because the biometrics changed or the screen lock was removed. |
| `UserAuthenticationCanceledError` | The user, the app or the system canceled the authentication prompt. |
| `UserAuthenticationFailedError` | The user didn't authenticate successfully, e.g. the fingerprint wasn't recognized. |
| `UserAuthenticationLockedOutError` | Biometrics are locked after too many failed attempts. They unlock when the user enters the device passcode, and on Android a first lockout also ends after 30 seconds. |
| `UserAuthenticationUnavailableError` | The user can't authenticate with the requested methods, e.g. no biometrics enrolled. |

## Migrating from 0.2.0

Keys created with 0.2.0 keep working. `sign` reads from the key itself whether it needs user authentication.

The minimum iOS version is now 16.4 (was 13.4), and the minimum Expo SDK is 53.

### Options instead of `biometricsBacked`

`generateKeypair` and `sign` no longer take a `biometricsBacked` argument. The defaults are the same as in 0.2.0: biometric authentication for every signature, the key is invalidated when the biometrics change, and Android stores it in StrongBox.

```typescript
// 0.2.0
await generateKeypair("my-key", false);
await sign("my-key", message, false);

// now
await generateKeypair("my-key", { userAuthentication: false });
await sign("my-key", message);
```

The third argument of `sign` now sets the texts of the authentication prompt, see [Sign data](#sign-data).

### Fallback secure environment removed

`setFallbackSecureEnvironment`, `shouldUseFallbackSecureEnvironment`, `isLocalSecureEnvironmentSupported` and the `SecureEnvironment` interface are removed. The functions now always use the device's secure environment, and `generateKeypair` throws a `SecureEnvironmentNotSupportedError` when the device doesn't have it.

If you used a fallback, check support with `isSecureEnvironmentSupported` and call your fallback yourself. Keep using the fallback for keys that are stored there:

- `isSecureEnvironmentSupported` doesn't always give the same result as 0.2.0. On iOS it now returns `false` without a Secure Enclave, e.g. in the simulator. On Android it returns `true` for every device with StrongBox, where 0.2.0 required KeyMint 1.0 or newer. Store where each key was created instead of checking support again.
- On Android devices without StrongBox you can store keys in the TEE with `minimumKeyStorage: "trustedEnvironment"` instead of using a fallback. Devices with StrongBox still store them there.

### Errors

- `nativeError` is replaced by `code`, the native error code (e.g. `ERR_KEY_NOT_FOUND`). The original error is in `cause`.
- The constructor takes options: `new SecureEnvironmentError(message, { keyId, code, cause })`. `SecureEnvironmentError.fromNative` is removed.
- Errors of the authentication prompt now have their own classes. On Android, 0.2.0 threw these as a plain `SecureEnvironmentError`.

`KeyNotFoundError` and `KeyAlreadyExistsError` are unchanged. The other error classes are removed:

| 0.2.0 | Now |
| --- | --- |
| `BiometricAuthenticationFailed` | `UserAuthenticationCanceledError`, `UserAuthenticationFailedError`, `UserAuthenticationLockedOutError` or `UserAuthenticationUnavailableError` |
| `NoHardwareKeyStore` | `SecureEnvironmentNotSupportedError` |
| `KeychainQueryError`, `CouldNotConvertIntoPublicKey`, `CouldNotConvertIntoExternalRepresentation`, `CouldNotCreateSignature`, `CouldNotGenerateKeyPair`, `NoSignatureOnCryptoObject`, `NotExecutedFromMainThread` | `SecureEnvironmentError` |

## Contributing

Is there something you'd like to fix or add? Great, we love community contributions! To get involved, please follow our [contribution guidelines](https://github.com/animo/.github/blob/main/CONTRIBUTING.md).

The tests run inside the example app with [React Native Harness](https://react-native-harness.dev). `pnpm test:ios` and `pnpm test:android` run them on a simulator or emulator, `pnpm test:ios:device` and `pnpm test:android:device` on a phone connected to your computer. Only a phone tests the secure hardware. See [AGENTS.md](AGENTS.md#tests) for details.

## License

This repository is licensed under the [Apache 2.0](./LICENSE) license.
