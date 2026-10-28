import {
  KeyAlreadyExistsError,
  KeyNotFoundError,
  type KeyStorage,
  SecureEnvironmentError,
  deleteKey,
  generateKeypair,
  getAttestationCertificateChain,
  getKeyStorage,
  getPublicBytesForKeyId,
  isSecureEnvironmentSupported,
  isUserAuthenticationAvailable,
  sign,
  withUserAuthentication,
} from '@animo-id/expo-secure-environment'
import { Key, KeyAlgorithm } from '@openwallet-foundation/askar-react-native'
import { useState } from 'react'
import { ActivityIndicator, Platform, Pressable, ScrollView, StatusBar, StyleSheet, Text, View } from 'react-native'

const isAndroid = Platform.OS === 'android'

const message = new TextEncoder().encode('Hello from the expo-secure-environment example')

let keyCounter = 0
const newKeyId = () => `example-${Date.now()}-${keyCounter++}`

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

const verifySignature = async (keyId: string, signature: Uint8Array) => {
  const publicKey = await getPublicBytesForKeyId(keyId)
  const key = Key.fromPublicBytes({ algorithm: KeyAlgorithm.EcSecp256r1, publicKey })
  if (!key.verifySignature({ message, signature })) throw new Error('The signature is invalid')
}

// Runs the test with new key ids, and deletes the keys afterwards, also when the test failed halfway
const withKeys = async (count: number, test: (keyIds: string[]) => Promise<string>) => {
  const keyIds = Array.from({ length: count }, newKeyId)
  try {
    return await test(keyIds)
  } finally {
    for (const keyId of keyIds) await deleteKey(keyId).catch(() => undefined)
  }
}

const withKey = (test: (keyId: string) => Promise<string>) => withKeys(1, ([keyId]) => test(keyId))

const expectError = async (operation: Promise<unknown>, ErrorClass: typeof SecureEnvironmentError) => {
  try {
    await operation
  } catch (error) {
    if (error instanceof ErrorClass) return
    throw error
  }
  throw new Error(`Expected a ${ErrorClass.name}, but the call succeeded`)
}

const toErrorText = (error: unknown) => (error instanceof Error ? `${error.name}: ${error.message}` : String(error))

interface ExampleTest {
  id: string
  title: string
  description: string
  // Shows an authentication prompt, so it's skipped when running all tests
  hasPrompt?: boolean
  androidOnly?: boolean
  run: (minimumKeyStorage: KeyStorage) => Promise<string>
}

interface ExampleSection {
  title: string
  description: string
  tests: ExampleTest[]
}

const sections: ExampleSection[] = [
  {
    title: 'Keys',
    description: 'Generating, reading and deleting keys. None of these need user authentication.',
    tests: [
      {
        id: 'generate',
        title: 'Generate, read and delete a key',
        description: 'Generates a P-256 key pair, reads the compressed public key, and deletes the key.',
        run: (minimumKeyStorage) =>
          withKey(async (keyId) => {
            await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })
            const publicKey = await getPublicBytesForKeyId(keyId)
            const storage = isAndroid ? `, stored in ${await getKeyStorage(keyId)}` : ''
            await deleteKey(keyId)
            await expectError(getPublicBytesForKeyId(keyId), KeyNotFoundError)
            return `Public key ${toHex(publicKey).slice(0, 16)}… (${publicKey.length} bytes)${storage}, deleted afterwards`
          }),
      },
      {
        id: 'duplicate',
        title: 'Reject a duplicate key id',
        description:
          'Generating a key with an id that is already in use throws a KeyAlreadyExistsError, and keeps the existing key.',
        run: (minimumKeyStorage) =>
          withKey(async (keyId) => {
            await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })
            const publicKey = await getPublicBytesForKeyId(keyId)
            await expectError(
              generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage }),
              KeyAlreadyExistsError
            )
            if (toHex(await getPublicBytesForKeyId(keyId)) !== toHex(publicKey)) {
              throw new Error('The existing key was replaced')
            }
            return 'Threw a KeyAlreadyExistsError, the existing key is unchanged'
          }),
      },
      {
        id: 'delete-twice',
        title: 'Reject deleting a missing key',
        description: 'Deleting a key that was already deleted throws a KeyNotFoundError.',
        run: (minimumKeyStorage) =>
          withKey(async (keyId) => {
            await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })
            await deleteKey(keyId)
            await expectError(deleteKey(keyId), KeyNotFoundError)
            return 'Threw a KeyNotFoundError'
          }),
      },
    ],
  },
  {
    title: 'Signing',
    description: 'Signs a message, and verifies the signature against the public key with Askar.',
    tests: [
      {
        id: 'sign',
        title: 'Sign without user authentication',
        description: 'For keys the app can use without asking the user, for example to bind data to this device.',
        run: (minimumKeyStorage) =>
          withKey(async (keyId) => {
            await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })
            await verifySignature(keyId, await sign(keyId, message))
            return 'The signature is valid'
          }),
      },
      {
        id: 'sign-biometric',
        title: 'Sign with biometrics',
        description:
          'The default. Every signature asks for Face ID, Touch ID or a fingerprint, so biometrics must be enrolled.',
        hasPrompt: true,
        run: (minimumKeyStorage) =>
          withKey(async (keyId) => {
            await generateKeypair(keyId, { minimumKeyStorage })
            const signature = await sign(keyId, message, { prompt: { title: 'Sign the test message' } })
            await verifySignature(keyId, signature)
            return 'The signature is valid'
          }),
      },
      {
        id: 'sign-biometric-or-passcode',
        title: 'Sign with biometrics or passcode',
        description:
          'The user can also use the device passcode, PIN or pattern. This works without enrolled biometrics.',
        hasPrompt: true,
        run: (minimumKeyStorage) =>
          withKey(async (keyId) => {
            await generateKeypair(keyId, {
              userAuthentication: { methods: ['biometric', 'deviceCredential'] },
              minimumKeyStorage,
            })
            const signature = await sign(keyId, message, {
              prompt: { title: 'Sign the test message', subtitle: 'Use biometrics or the device passcode' },
            })
            await verifySignature(keyId, signature)
            return 'The signature is valid'
          }),
      },
      {
        id: 'sign-multiple',
        title: 'Sign three times with one authentication',
        description:
          'withUserAuthentication asks at the first signature, and the next two reuse that authentication. Its sign throws after the callback returned. On Android this needs keys with a validitySeconds above 0.',
        hasPrompt: true,
        run: (minimumKeyStorage) =>
          withKeys(3, async (keyIds) => {
            for (const keyId of keyIds) {
              await generateKeypair(keyId, {
                userAuthentication: { methods: ['biometric', 'deviceCredential'], validitySeconds: 10 },
                minimumKeyStorage,
              })
            }

            const { session, signatures } = await withUserAuthentication(
              async (session) => {
                const signatures: Uint8Array[] = []
                for (const keyId of keyIds) signatures.push(await session.sign(keyId, message))
                return { session, signatures }
              },
              { prompt: { title: 'Sign three test messages' } }
            )

            for (const [index, keyId] of keyIds.entries()) await verifySignature(keyId, signatures[index])
            await expectError(session.sign(keyIds[0], message), SecureEnvironmentError)
            return `${signatures.length} valid signatures after one authentication, the ended session can't sign`
          }),
      },
      {
        id: 'sign-multiple-mixed',
        title: 'Sign with and without user authentication',
        description:
          'withUserAuthentication with a key without user authentication first. That key signs without asking, the second key asks, and the third reuses that authentication. On Android this needs keys with a validitySeconds above 0.',
        hasPrompt: true,
        run: (minimumKeyStorage) =>
          withKeys(3, async (keyIds) => {
            for (const [index, keyId] of keyIds.entries()) {
              await generateKeypair(keyId, {
                userAuthentication:
                  index === 0 ? false : { methods: ['biometric', 'deviceCredential'], validitySeconds: 10 },
                minimumKeyStorage,
              })
            }

            const signatures = await withUserAuthentication(
              async (session) => {
                const signatures: Uint8Array[] = []
                for (const keyId of keyIds) signatures.push(await session.sign(keyId, message))
                return signatures
              },
              { prompt: { title: 'Sign three test messages' } }
            )

            for (const [index, keyId] of keyIds.entries()) await verifySignature(keyId, signatures[index])
            return `${signatures.length} valid signatures after one authentication`
          }),
      },
      {
        id: 'sign-multiple-passcode',
        title: 'Sign twice with one passcode entry',
        description:
          'withUserAuthentication with keys that only accept the device passcode. It asks for the passcode once, also on devices with biometrics, and both signatures reuse it.',
        hasPrompt: true,
        run: (minimumKeyStorage) =>
          withKeys(2, async (keyIds) => {
            for (const keyId of keyIds) {
              await generateKeypair(keyId, {
                userAuthentication: { methods: ['deviceCredential'], validitySeconds: 10 },
                minimumKeyStorage,
              })
            }

            const signatures = await withUserAuthentication(
              async (session) => {
                const signatures: Uint8Array[] = []
                for (const keyId of keyIds) signatures.push(await session.sign(keyId, message))
                return signatures
              },
              { prompt: { title: 'Sign two test messages' } }
            )

            for (const [index, keyId] of keyIds.entries()) await verifySignature(keyId, signatures[index])
            return `${signatures.length} valid signatures after one passcode entry`
          }),
      },
      {
        id: 'sign-concurrently',
        title: 'Sign with two keys at once',
        description:
          'Starts two signatures at the same time, with keys that require authentication for every signature. The prompts show one after the other, and each signature is valid for its own key. iOS shows one prompt at a time and cancels the first.',
        hasPrompt: true,
        androidOnly: true,
        run: (minimumKeyStorage) =>
          withKeys(2, async (keyIds) => {
            for (const keyId of keyIds) {
              await generateKeypair(keyId, {
                userAuthentication: { methods: ['biometric', 'deviceCredential'] },
                minimumKeyStorage,
              })
            }

            const signatures = await Promise.all(
              keyIds.map((keyId, index) =>
                sign(keyId, message, { prompt: { title: `Sign with key ${index + 1} of 2` } })
              )
            )

            for (const [index, keyId] of keyIds.entries()) await verifySignature(keyId, signatures[index])
            return 'Two prompts, both signatures are valid for their own key'
          }),
      },
    ],
  },
  {
    title: 'Key attestation',
    description:
      'A certificate chain from the secure hardware that proves the key was generated there. iOS has no key attestation for Secure Enclave keys.',
    tests: [
      {
        id: 'attestation',
        title: 'Get a key attestation',
        description:
          'Generates a key with an attestation challenge, normally a nonce from the verifier, and reads the certificate chain.',
        androidOnly: true,
        run: (minimumKeyStorage) =>
          withKey(async (keyId) => {
            const attestationChallenge = new TextEncoder().encode(`challenge-${Date.now()}`)
            await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage, attestationChallenge })
            const chain = await getAttestationCertificateChain(keyId)
            return `A chain of ${chain.length} certificates`
          }),
      },
    ],
  },
]

const testsWithoutPrompt = sections
  .flatMap((section) => section.tests)
  .filter((test) => !test.hasPrompt && (isAndroid || !test.androidOnly))

const keyStorageOptions: { value: KeyStorage; label: string }[] = [
  { value: 'strongBox', label: 'StrongBox' },
  { value: 'trustedEnvironment', label: 'TEE' },
  { value: 'software', label: 'Software' },
]

type TestResult = { status: 'running' } | { status: 'passed' | 'failed'; detail: string }

export default function App() {
  const [support] = useState(() => ({
    strongBox: isSecureEnvironmentSupported({ minimumKeyStorage: 'strongBox' }),
    trustedEnvironment: isSecureEnvironmentSupported({ minimumKeyStorage: 'trustedEnvironment' }),
    software: isSecureEnvironmentSupported({ minimumKeyStorage: 'software' }),
  }))
  const [userAuthentication] = useState(() => ({
    biometric: isUserAuthenticationAvailable(),
    biometricOrPasscode: isUserAuthenticationAvailable({ methods: ['biometric', 'deviceCredential'] }),
  }))
  const [minimumKeyStorage, setMinimumKeyStorage] = useState<KeyStorage>(
    keyStorageOptions.find(({ value }) => support[value])?.value ?? 'software'
  )
  const [results, setResults] = useState<Record<string, TestResult>>({})
  const [isRunningAll, setIsRunningAll] = useState(false)

  const runTest = async (test: ExampleTest) => {
    setResults((results) => ({ ...results, [test.id]: { status: 'running' } }))
    try {
      const detail = await test.run(minimumKeyStorage)
      setResults((results) => ({ ...results, [test.id]: { status: 'passed', detail } }))
    } catch (error) {
      setResults((results) => ({ ...results, [test.id]: { status: 'failed', detail: toErrorText(error) } }))
    }
  }

  const runTestsWithoutPrompt = async () => {
    setIsRunningAll(true)
    for (const test of testsWithoutPrompt) await runTest(test)
    setIsRunningAll(false)
  }

  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.content}>
      <StatusBar barStyle="dark-content" />
      <Text style={styles.title}>Expo Secure Environment</Text>
      <Text style={styles.subtitle}>Runs the library against the secure hardware of this device.</Text>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>{isAndroid ? 'Minimum key storage' : 'Secure Enclave'}</Text>
        {isAndroid ? (
          <>
            <Text style={styles.description}>
              The least secure storage the tests accept for their keys. Keys are stored in StrongBox when the device has
              it, otherwise in the TEE, or in software on devices without a TEE such as emulators.
            </Text>
            <View style={styles.segments}>
              {keyStorageOptions.map(({ value, label }) => (
                <Pressable
                  key={value}
                  onPress={() => setMinimumKeyStorage(value)}
                  style={[styles.segment, minimumKeyStorage === value && styles.segmentSelected]}
                >
                  <Text style={[styles.segmentLabel, minimumKeyStorage === value && styles.segmentLabelSelected]}>
                    {label}
                  </Text>
                  <Text style={[styles.segmentSupport, !support[value] && styles.textFailed]}>
                    {support[value] ? 'Supported' : 'Not supported'}
                  </Text>
                </Pressable>
              ))}
            </View>
          </>
        ) : (
          <Text style={[styles.description, !support.strongBox && styles.textFailed]}>
            {support.strongBox
              ? 'Available, the tests generate their keys in the Secure Enclave.'
              : 'Not available, for example in the simulator. Generating a key throws a SecureEnvironmentNotSupportedError.'}
          </Text>
        )}
        <Text style={[styles.cardTitle, styles.cardSection]}>User authentication</Text>
        <Text style={styles.description}>
          What the tests with a prompt need. Without it, generating their keys throws a
          UserAuthenticationUnavailableError.
        </Text>
        <View style={styles.segments}>
          <Availability label="Biometrics" isAvailable={userAuthentication.biometric} />
          <Availability label="Biometrics or passcode" isAvailable={userAuthentication.biometricOrPasscode} />
        </View>
        <Pressable
          onPress={runTestsWithoutPrompt}
          disabled={isRunningAll}
          style={({ pressed }) => [styles.primaryButton, (pressed || isRunningAll) && styles.pressed]}
        >
          {isRunningAll ? (
            <ActivityIndicator color={colors.onPrimary} />
          ) : (
            <Text style={styles.primaryButtonLabel}>Run the {testsWithoutPrompt.length} tests without a prompt</Text>
          )}
        </Pressable>
      </View>

      {sections.map((section) => (
        <View key={section.title} style={styles.section}>
          <Text style={styles.sectionTitle}>{section.title}</Text>
          <Text style={styles.sectionDescription}>{section.description}</Text>
          {section.tests.map((test) => (
            <TestCard key={test.id} test={test} result={results[test.id]} onRun={() => runTest(test)} />
          ))}
        </View>
      ))}
    </ScrollView>
  )
}

function TestCard({ test, result, onRun }: { test: ExampleTest; result?: TestResult; onRun: () => void }) {
  const isUnavailable = test.androidOnly && !isAndroid
  const isRunning = result?.status === 'running'

  return (
    <View style={[styles.card, isUnavailable && styles.cardUnavailable]}>
      <View style={styles.cardHeader}>
        <Text style={[styles.cardTitle, styles.cardHeaderTitle]}>{test.title}</Text>
        {result?.status === 'passed' && <Badge label="Passed" style={styles.badgePassed} />}
        {result?.status === 'failed' && <Badge label="Failed" style={styles.badgeFailed} />}
      </View>
      <Text style={styles.description}>{test.description}</Text>
      {result && result.status !== 'running' && (
        <Text style={[styles.detail, result.status === 'failed' ? styles.detailFailed : styles.detailPassed]}>
          {result.detail}
        </Text>
      )}
      <View style={styles.cardFooter}>
        <View style={styles.tags}>
          {test.hasPrompt && <Badge label="Prompt" />}
          {test.androidOnly && <Badge label="Android only" />}
        </View>
        <Pressable
          onPress={onRun}
          disabled={isRunning || isUnavailable}
          style={({ pressed }) => [
            styles.button,
            (pressed || isRunning) && styles.pressed,
            isUnavailable && styles.disabled,
          ]}
        >
          {isRunning ? (
            <ActivityIndicator size="small" color={colors.primary} />
          ) : (
            <Text style={styles.buttonLabel}>{result ? 'Run again' : 'Run'}</Text>
          )}
        </Pressable>
      </View>
    </View>
  )
}

function Availability({ label, isAvailable }: { label: string; isAvailable: boolean }) {
  return (
    <View style={styles.segment}>
      <Text style={styles.segmentLabel}>{label}</Text>
      <Text style={[styles.segmentSupport, !isAvailable && styles.textFailed]}>
        {isAvailable ? 'Available' : 'Not available'}
      </Text>
    </View>
  )
}

function Badge({ label, style }: { label: string; style?: object }) {
  return (
    <View style={[styles.badge, style]}>
      <Text style={styles.badgeLabel}>{label}</Text>
    </View>
  )
}

const colors = {
  background: '#F2F4F7',
  card: '#FFFFFF',
  border: '#E4E7EC',
  text: '#101828',
  muted: '#667085',
  primary: '#3538CD',
  onPrimary: '#FFFFFF',
  primaryTint: '#EEF4FF',
  passed: '#067647',
  passedTint: '#ECFDF3',
  failed: '#B42318',
  failedTint: '#FEF3F2',
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: colors.background,
  },
  content: {
    paddingHorizontal: 16,
    paddingTop: isAndroid ? (StatusBar.currentHeight ?? 24) + 24 : 72,
    paddingBottom: 48,
  },
  title: {
    fontSize: 28,
    fontWeight: '700',
    color: colors.text,
  },
  subtitle: {
    marginTop: 4,
    marginBottom: 20,
    fontSize: 15,
    color: colors.muted,
  },
  section: {
    marginTop: 20,
  },
  sectionTitle: {
    fontSize: 13,
    fontWeight: '600',
    letterSpacing: 0.6,
    textTransform: 'uppercase',
    color: colors.muted,
  },
  sectionDescription: {
    marginTop: 4,
    marginBottom: 10,
    fontSize: 14,
    color: colors.muted,
  },
  card: {
    marginBottom: 12,
    padding: 16,
    borderRadius: 14,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    backgroundColor: colors.card,
  },
  cardSection: {
    marginTop: 20,
  },
  cardUnavailable: {
    opacity: 0.6,
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 8,
  },
  cardHeaderTitle: {
    flex: 1,
  },
  cardTitle: {
    fontSize: 17,
    fontWeight: '600',
    color: colors.text,
  },
  cardFooter: {
    marginTop: 14,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  description: {
    marginTop: 6,
    fontSize: 14,
    lineHeight: 20,
    color: colors.muted,
  },
  detail: {
    marginTop: 12,
    padding: 10,
    borderRadius: 8,
    fontSize: 13,
    lineHeight: 18,
    fontFamily: Platform.select({ ios: 'Menlo', default: 'monospace' }),
  },
  detailPassed: {
    color: colors.passed,
    backgroundColor: colors.passedTint,
  },
  detailFailed: {
    color: colors.failed,
    backgroundColor: colors.failedTint,
  },
  textFailed: {
    color: colors.failed,
  },
  tags: {
    flexDirection: 'row',
    gap: 6,
  },
  badge: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 999,
    backgroundColor: colors.background,
  },
  badgePassed: {
    backgroundColor: colors.passedTint,
  },
  badgeFailed: {
    backgroundColor: colors.failedTint,
  },
  badgeLabel: {
    fontSize: 12,
    fontWeight: '600',
    color: colors.text,
  },
  button: {
    minWidth: 96,
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 999,
    backgroundColor: colors.primaryTint,
  },
  buttonLabel: {
    fontSize: 15,
    fontWeight: '600',
    color: colors.primary,
  },
  primaryButton: {
    marginTop: 16,
    alignItems: 'center',
    paddingVertical: 12,
    borderRadius: 10,
    backgroundColor: colors.primary,
  },
  primaryButtonLabel: {
    fontSize: 15,
    fontWeight: '600',
    color: colors.onPrimary,
  },
  pressed: {
    opacity: 0.7,
  },
  disabled: {
    opacity: 0.4,
  },
  segments: {
    marginTop: 12,
    flexDirection: 'row',
    gap: 8,
  },
  segment: {
    flex: 1,
    padding: 10,
    borderRadius: 10,
    borderWidth: 1.5,
    borderColor: colors.border,
  },
  segmentSelected: {
    borderColor: colors.primary,
    backgroundColor: colors.primaryTint,
  },
  segmentLabel: {
    fontSize: 15,
    fontWeight: '600',
    color: colors.text,
  },
  segmentLabelSelected: {
    color: colors.primary,
  },
  segmentSupport: {
    marginTop: 2,
    fontSize: 13,
    color: colors.passed,
  },
})
