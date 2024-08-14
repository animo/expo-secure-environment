import { Platform } from "expo-modules-core";
import ExpoSecureEnvironmentModule from "./ExpoSecureEnvironmentModule";
import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";

export function generateKeypair(id: string, biometricsBacked: boolean = true) {
  ExpoSecureEnvironmentModule.generateKeypair(id, biometricsBacked);
}

export function getPublicBytesForKeyId(keyId: string): Uint8Array {
  const publicBytes = ExpoSecureEnvironmentModule.getPublicBytesForKeyId(keyId);

  if (Platform.OS === "android") {
    let spki = AsnParser.parse(publicBytes, SubjectPublicKeyInfo);
    return new Uint8Array(spki.subjectPublicKey);
  }

  return publicBytes;
}

export async function sign(
  keyId: string,
  message: Uint8Array,
  biometricsBacked: boolean = true
): Promise<Uint8Array> {
  const signature =
    Platform.OS === "ios"
      ? await ExpoSecureEnvironmentModule.sign(keyId, message)
      : await ExpoSecureEnvironmentModule.sign(
          keyId,
          message,
          biometricsBacked
        );

  const { r, s } = AsnParser.parse(signature, ECDSASigValue);
  const newR = new Uint8Array(r.byteLength === 33 ? r.slice(1) : r);
  const newS = new Uint8Array(s.byteLength === 33 ? s.slice(1) : s);
  return new Uint8Array([...newR, ...newS]);
}
