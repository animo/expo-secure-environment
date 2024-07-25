import * as React from 'react';

import { ExpoSecureEnvironmentViewProps } from './ExpoSecureEnvironment.types';

export default function ExpoSecureEnvironmentView(props: ExpoSecureEnvironmentViewProps) {
  return (
    <div>
      <span>{props.name}</span>
    </div>
  );
}
