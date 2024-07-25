import { NativeModulesProxy, EventEmitter, Subscription } from 'expo-modules-core';

// Import the native module. On web, it will be resolved to ExpoSecureEnvironment.web.ts
// and on native platforms to ExpoSecureEnvironment.ts
import ExpoSecureEnvironmentModule from './ExpoSecureEnvironmentModule';
import ExpoSecureEnvironmentView from './ExpoSecureEnvironmentView';
import { ChangeEventPayload, ExpoSecureEnvironmentViewProps } from './ExpoSecureEnvironment.types';

// Get the native constant value.
export const PI = ExpoSecureEnvironmentModule.PI;

export function hello(): string {
  return ExpoSecureEnvironmentModule.hello();
}

export async function setValueAsync(value: string) {
  return await ExpoSecureEnvironmentModule.setValueAsync(value);
}

const emitter = new EventEmitter(ExpoSecureEnvironmentModule ?? NativeModulesProxy.ExpoSecureEnvironment);

export function addChangeListener(listener: (event: ChangeEventPayload) => void): Subscription {
  return emitter.addListener<ChangeEventPayload>('onChange', listener);
}

export { ExpoSecureEnvironmentView, ExpoSecureEnvironmentViewProps, ChangeEventPayload };
