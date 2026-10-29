import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { CallToAction } from '../components/CallToAction';

interface Scene5CTAProps {
  isVertical?: boolean;
  language?: 'kh' | 'en';
}

export const Scene5CTA: React.FC<Scene5CTAProps> = ({
  isVertical = true,
  language = 'kh',
}) => {
  const frame = useCurrentFrame();

  // Scene fade in & final video fade out (total 210 frames)
  const opacity = interpolate(frame, [0, 15, 195, 210], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill
      style={{
        opacity,
        overflow: 'hidden',
      }}
    >
      <CyberBackground glowMode="cyan" gridSpeed={1.0} isVertical={isVertical} />

      {/* Main Center Call to Action Container */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          // Mobile safe area padding (protecting TikTok bottom caption area & right-side buttons)
          paddingTop: isVertical ? 60 : 20,
          paddingBottom: isVertical ? 140 : 20,
          zIndex: 20,
        }}
      >
        <CallToAction isVertical={isVertical} language={language} />
      </div>
    </AbsoluteFill>
  );
};