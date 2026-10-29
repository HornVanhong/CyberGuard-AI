import React from 'react';
import { AbsoluteFill } from 'remotion';
import { CyberGuardVideo } from './CyberGuardVideo';

export const CyberGuardVideoVertical: React.FC = () => {
  return (
    <AbsoluteFill
      style={{
        backgroundColor: '#0a0e17',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
      }}
    >
      {/* Background ambient scale */}
      <div
        style={{
          width: 1920,
          height: 1080,
          transform: 'scale(1.15)',
          transformOrigin: 'center center',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <CyberGuardVideo />
      </div>
    </AbsoluteFill>
  );
};
