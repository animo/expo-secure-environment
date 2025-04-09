import { deleteKey, generateKeypair, getPublicBytesForKeyId, sign } from '@animo-id/expo-secure-environment'
import { KeyAlgs, LocalKeyHandle, ariesAskar } from '@hyperledger/aries-askar-react-native'
import { useState } from 'react'
import { Button, StyleSheet, Text, View } from 'react-native'

export default function App() {
  const [isBioFlowDone, setIsBioFlowDone] = useState<boolean>()
  const [isNonBioFlowDone, setIsNonBioFlowDone] = useState<boolean>()

  const testKeyDoubleGenerate = async () => {
    const id = new Date().toString()
    generateKeypair(id, false)
    generateKeypair(id, false)
  }

  const testKeyDoubleDelete = async () => {
    const id = new Date().toString()
    generateKeypair(id, false)
    deleteKey(id)
    deleteKey(id)
  }

  const testBiometrics = async () => {
    try {
      const id = new Date().toString()
      generateKeypair(id, true)
      const publicKey = await getPublicBytesForKeyId(id)
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

      deleteKey(id)

      setIsBioFlowDone(isValid)
    } catch (e) {
      console.error('Error signing with biometrics enabled', e)
    }
  }

  const testNoBiometrics = async () => {
    try {
      const id = new Date().toString()
      generateKeypair(id, false)
      const publicKey = await getPublicBytesForKeyId(id)
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

      deleteKey(id)

      setIsNonBioFlowDone(isValid)
    } catch (e) {
      console.error('Error signing with biometrics disabled', e)
    }
  }

  return (
    <View style={styles.container}>
      <Button title="test key double generate" onPress={testKeyDoubleGenerate} />
      <Button title="test key double delete" onPress={testKeyDoubleDelete} />
      <Button title="test biometrics" onPress={testBiometrics} />
      {isBioFlowDone !== undefined && <Text>Biometrics flow is working!</Text>}
      {isBioFlowDone === false && <Text>Signature is invalid</Text>}
      {isBioFlowDone === true && <Text>Signature is valid</Text>}
      <Button title="test without biometrics" onPress={testNoBiometrics} />
      {isNonBioFlowDone !== undefined && <Text>Non-biometrics flow is working!</Text>}
      {isNonBioFlowDone === false && <Text>Signature is invalid</Text>}
      {isNonBioFlowDone === true && <Text>Signature is valid</Text>}
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
