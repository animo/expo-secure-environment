import {
  ariesAskar,
  KeyAlgs,
  LocalKeyHandle,
} from "@hyperledger/aries-askar-react-native";
import {
  sign,
  generateKeypair,
  getPublicBytesForKeyId,
} from "expo-secure-environment";
import { Button } from "react-native";
import { StyleSheet, View } from "react-native";

export default function App() {
  const test = async () => {
    const id = "keyid";
    generateKeypair(id, true);
    const publicKey = getPublicBytesForKeyId(id);
    const key = ariesAskar.keyFromPublicBytes({
      algorithm: KeyAlgs.EcSecp256r1,
      publicKey,
    });
    const kHandle = new LocalKeyHandle(key.handle);
    const message = new Uint8Array(10).fill(10);
    const signature = await sign(id, new Uint8Array(message));
    const isValid = ariesAskar.keyVerifySignature({
      message,
      signature,
      localKeyHandle: kHandle,
    });

    console.log(isValid);
  };

  return (
    <View style={styles.container}>
      <Button title="test" onPress={test} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
  },
});
