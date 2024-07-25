import { requireNativeViewManager } from 'expo-modules-core';
import * as React from 'react';

import { ExpoSecureEnvironmentViewProps } from './ExpoSecureEnvironment.types';

const NativeView: React.ComponentType<ExpoSecureEnvironmentViewProps> =
  requireNativeViewManager('ExpoSecureEnvironment');

export default function ExpoSecureEnvironmentView(props: ExpoSecureEnvironmentViewProps) {
  return <NativeView {...props} />;
}
