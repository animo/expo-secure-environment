import { StyleSheet, Text, View } from 'react-native';

import * as ExpoSecureEnvironment from 'expo-secure-environment';

export default function App() {
  return (
    <View style={styles.container}>
      <Text>{ExpoSecureEnvironment.hello()}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});
