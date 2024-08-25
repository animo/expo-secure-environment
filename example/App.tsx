import { generateKeypair, getPublicBytesForKeyId, sign } from '@animo-id/expo-secure-environment'
import { KeyAlgs, LocalKeyHandle, ariesAskar } from '@hyperledger/aries-askar-react-native'
import { Button } from 'react-native'
import { StyleSheet, View } from 'react-native'

export default function App() {
  const testBiometrics = async () => {
    try {
      const id = new Date().toString()
      generateKeypair(id, true)
      const publicKey = getPublicBytesForKeyId(id)
      const key = ariesAskar.keyFromPublicBytes({
        algorithm: KeyAlgs.EcSecp256r1,
        publicKey,
      })
      const kHandle = new LocalKeyHandle(key.handle)
      const message = new Uint8Array(10).fill(10)
      const signature = await sign(id, new Uint8Array(message), true)
      const isValid = ariesAskar.keyVerifySignature({
        message,
        signature,
        localKeyHandle: kHandle,
      })

      console.log('Signing with biometrics enabled isValid: ', isValid)
    } catch (e) {
      console.error('Error signing with biometrics enabled', e)
    }
  }

  const testNoBiometrics = async () => {
    try {
      const id = new Date().toString()
      generateKeypair(id, false)
      const publicKey = getPublicBytesForKeyId(id)
      const key = ariesAskar.keyFromPublicBytes({
        algorithm: KeyAlgs.EcSecp256r1,
        publicKey,
      })
      const kHandle = new LocalKeyHandle(key.handle)
      const message = new Uint8Array(10).fill(10)
      const signature = await sign(id, new Uint8Array(message), false)
      const isValid = ariesAskar.keyVerifySignature({
        message,
        signature,
        localKeyHandle: kHandle,
      })

      console.log('Signing with biometrics disabled isValid: ', isValid)
    } catch (e) {
      console.error('Error signing with biometrics disabled', e)
    }
  }

  return (
    <View style={styles.container}>
      <Button title="test biometrics" onPress={testBiometrics} />
      <Button title="test without biometrics" onPress={testNoBiometrics} />
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
})
