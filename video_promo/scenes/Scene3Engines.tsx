import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { EngineGrid } from '../components/EngineGrid';

export const Scene3Engines: React.FC = () => {
  const frame = useCurrentFrame();

  // Scene transition
  const sceneOpacity = interpolate(frame, [0, 15, 195, 210], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity,
      }}
    >
      <CyberBackground glowMode="emerald" />

      {/* Top Header */}
      <div
        style={{
          position: 'absolute',
          top: 40,
          left: 80,
          right: 80,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', gap: 14 }}>
          <div
            style={{
              padding: '6px 16px',
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              border: '1px solid rgba(16, 185, 129, 0.45)',
              borderRadius: 20,
              fontSize: 12,
              fontWeight: 800,
              color: '#10b981',
              fontFamily: 'Consolas, monospace',
            }}
          >
            ● MULTI-ENGINE SECURITY PIPELINE
          </div>
          <div
            style={{
              padding: '6px 16px',
              backgroundColor: 'rgba(0, 240, 255, 0.15)',
              border: '1px solid rgba(0, 240, 255, 0.45)',
              borderRadius: 20,
              fontSize: 12,
              fontWeight: 800,
              color: '#00f0ff',
              fontFamily: 'Consolas, monospace',
            }}
          >
            ACTIVE ADAPTERS: 12/12
          </div>
        </div>

        <div style={{ color: '#10b981', fontFamily: 'Consolas, monospace', fontSize: 13 }}>
          LATENCY: 0ms HOST PERSISTENCE // READ-ONLY CONTAINER
        </div>
      </div>

      {/* Section Title */}
      <div
        style={{
          position: 'absolute',
          top: 100,
          left: 0,
          right: 0,
          textAlign: 'center',
          zIndex: 10,
        }}
      >
        <div
          style={{
            fontSize: 42,
            fontWeight: 900,
            color: '#ffffff',
            letterSpacing: '1px',
            fontFamily: '"Montserrat", "Inter", sans-serif',
            textShadow: '0 0 25px rgba(16, 185, 129, 0.4)',
          }}
        >
          12 Heavy-Duty Inspection Engines
        </div>
        <div style={{ fontSize: 16, color: '#9ca3af', marginTop: 6, fontFamily: 'Consolas, monospace' }}>
          Simultaneous heuristic matching, binary decompilation, and behavioral threat analysis
        </div>
      </div>

      {/* 12 Engine Cards Grid */}
      <div
        style={{
          position: 'absolute',
          top: 215,
          left: 60,
          right: 60,
          zIndex: 10,
        }}
      >
        <EngineGrid />
      </div>
    </AbsoluteFill>
  );
};
