import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';

interface SceneTransitionProps {
  durationInFrames?: number;
}

export const SceneTransition: React.FC<SceneTransitionProps> = ({
  durationInFrames = 15,
}) => {
  const frame = useCurrentFrame();

  const progress = interpolate(frame, [0, durationInFrames], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const flashOpacity = interpolate(
    progress,
    [0, 0.4, 0.7, 1],
    [0, 0.7, 0.3, 0]
  );

  const scanlineY = progress * 100;

  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 100,
        overflow: 'hidden',
      }}
    >
      {/* Glitch Flash */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundColor: '#00F0FF',
          opacity: flashOpacity,
          mixBlendMode: 'screen',
        }}
      />

      {/* High-speed wipe laser */}
      <div
        style={{
          position: 'absolute',
          top: `${scanlineY}%`,
          left: 0,
          right: 0,
          height: 6,
          background: 'linear-gradient(90deg, transparent, #FFFFFF, #00F0FF, transparent)',
          boxShadow: '0 0 25px #00F0FF',
          opacity: flashOpacity > 0 ? 1 : 0,
        }}
      />
    </div>
  );
};