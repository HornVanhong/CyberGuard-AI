import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { CallToAction } from '../components/CallToAction';

export const Scene5CallToAction: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Scene transition
  const sceneOpacity = interpolate(frame, [0, 15, 165, 180], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const contentSpring = spring({
    fps,
    frame,
    config: { damping: 15, mass: 0.5, stiffness: 100 },
  });

  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity,
      }}
    >
      <CyberBackground glowMode="cyan" />

      {/* Main Container */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 10,
          textAlign: 'center',
          padding: '0 40px',
        }}
      >
        {/* Top Mini Pill */}
        <div
          style={{
            padding: '6px 18px',
            backgroundColor: 'rgba(0, 240, 255, 0.15)',
            border: '1px solid rgba(0, 240, 255, 0.45)',
            borderRadius: 20,
            fontSize: 12,
            fontWeight: 800,
            color: '#00f0ff',
            fontFamily: 'Consolas, monospace',
            marginBottom: 20,
            letterSpacing: '2px',
          }}
        >
          ● GET STARTED IN SECONDS
        </div>

        {/* Main Headline */}
        <div style={{ transform: `scale(${contentSpring})`, marginBottom: 30 }}>
          <div
            style={{
              fontSize: 54,
              fontWeight: 900,
              fontFamily: '"Montserrat", "Inter", sans-serif',
              letterSpacing: '-0.5px',
              color: '#ffffff',
              textShadow: '0 0 35px rgba(0, 240, 255, 0.5)',
            }}
          >
            Protect Your Digital Life Today
          </div>
          <div
            style={{
              fontSize: 18,
              color: '#9ca3af',
              fontFamily: 'Consolas, monospace',
              marginTop: 8,
              letterSpacing: '1px',
            }}
          >
            Forward or upload files directly on Telegram for real-time defense.
          </div>
        </div>

        {/* 3D Telegram Button + QR Code */}
        <div style={{ transform: `scale(${contentSpring})` }}>
          <CallToAction />
        </div>
      </div>
    </AbsoluteFill>
  );
};
