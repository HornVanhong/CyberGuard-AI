import React, { useMemo } from 'react';
import { AbsoluteFill, useCurrentFrame } from 'remotion';

interface CyberBackgroundProps {
  glowMode?: 'cyan' | 'crimson' | 'emerald';
  gridSpeed?: number;
}

export const CyberBackground: React.FC<CyberBackgroundProps> = ({
  glowMode = 'cyan',
  gridSpeed = 1.2,
}) => {
  const frame = useCurrentFrame();

  const colors = {
    cyan: { primary: '#00f0ff', secondary: '#0051ff', ambient: 'rgba(0, 240, 255, 0.12)' },
    crimson: { primary: '#ef4444', secondary: '#991b1b', ambient: 'rgba(239, 68, 68, 0.15)' },
    emerald: { primary: '#10b981', secondary: '#047857', ambient: 'rgba(16, 185, 129, 0.12)' },
  }[glowMode];

  // Floating cybersecurity telemetry & hex particles
  const particles = useMemo(() => {
    const symbols = ['0x4A', '0x9F', 'TCP', 'TLS', 'YARA', 'SHA', 'SIG', 'PE', 'CVE', 'HEX', '0', '1'];
    return Array.from({ length: 40 }).map((_, i) => ({
      id: i,
      char: symbols[i % symbols.length],
      x: ((i * 137.5) % 96) + 2,
      baseY: ((i * 83.3) % 94) + 3,
      speed: 0.12 + ((i % 5) * 0.05),
      size: i % 4 === 0 ? 11 : 3 + (i % 3) * 2,
      isText: i % 3 === 0,
      opacity: 0.15 + ((i % 4) * 0.1),
    }));
  }, []);

  const pulse = Math.sin(frame * 0.08) * 0.18 + 0.82;
  const gridOffsetY = (frame * gridSpeed) % 40;

  return (
    <AbsoluteFill
      style={{
        backgroundColor: '#0a0e17',
        overflow: 'hidden',
        pointerEvents: 'none',
      }}
    >
      {/* Deep gradient background */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: `radial-gradient(circle at 50% 40%, ${colors.secondary}1a 0%, #0a0e17 78%)`,
        }}
      />

      {/* Primary ambient glow orb */}
      <div
        style={{
          position: 'absolute',
          top: '20%',
          left: '20%',
          width: 700,
          height: 700,
          borderRadius: '50%',
          background: `radial-gradient(circle, ${colors.primary}18 0%, transparent 70%)`,
          filter: 'blur(90px)',
          transform: `scale(${pulse})`,
        }}
      />

      {/* Secondary ambient glow orb */}
      <div
        style={{
          position: 'absolute',
          bottom: '15%',
          right: '20%',
          width: 750,
          height: 750,
          borderRadius: '50%',
          background: `radial-gradient(circle, ${colors.secondary}22 0%, transparent 70%)`,
          filter: 'blur(100px)',
          transform: `scale(${1.9 - pulse})`,
        }}
      />

      {/* Perspective / Cyber HUD grid */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: `
            linear-gradient(to right, rgba(0, 240, 255, 0.05) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(0, 240, 255, 0.05) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          backgroundPosition: `0px ${gridOffsetY}px`,
          opacity: 0.85,
        }}
      />

      {/* Animated horizontal laser scanning line */}
      <div
        style={{
          position: 'absolute',
          left: 0,
          right: 0,
          height: 2,
          top: `${((frame * 3) % 1150) - 50}px`,
          background: `linear-gradient(90deg, transparent 0%, ${colors.primary}88 50%, transparent 100%)`,
          boxShadow: `0 0 16px ${colors.primary}`,
          opacity: 0.5,
        }}
      />

      {/* Drifting Cyber Particles */}
      {particles.map((p) => {
        const currentY = (p.baseY - frame * p.speed) % 110;
        const normalizedY = currentY < -10 ? currentY + 120 : currentY;

        return (
          <div
            key={p.id}
            style={{
              position: 'absolute',
              left: `${p.x}%`,
              top: `${normalizedY}%`,
              opacity: p.opacity,
              fontFamily: 'Consolas, monospace',
              fontSize: p.isText ? p.size : 0,
              color: colors.primary,
              textShadow: `0 0 8px ${colors.primary}`,
            }}
          >
            {p.isText ? (
              p.char
            ) : (
              <div
                style={{
                  width: p.size,
                  height: p.size,
                  borderRadius: '50%',
                  backgroundColor: colors.primary,
                  boxShadow: `0 0 8px ${colors.primary}`,
                }}
              />
            )}
          </div>
        );
      })}

      {/* CRT Scanline Overlay */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: 'repeating-linear-gradient(0deg, rgba(0,0,0,0.18) 0px, rgba(0,0,0,0.18) 1px, transparent 2px, transparent 4px)',
          opacity: 0.6,
          pointerEvents: 'none',
        }}
      />

      {/* Dark Vignette */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: 'radial-gradient(ellipse at center, transparent 45%, rgba(10, 14, 23, 0.88) 100%)',
        }}
      />

      {/* Futuristic HUD Corner Brackets */}
      <div style={{ position: 'absolute', top: 32, left: 32, width: 28, height: 28, borderTop: `2px solid ${colors.primary}66`, borderLeft: `2px solid ${colors.primary}66` }} />
      <div style={{ position: 'absolute', top: 32, right: 32, width: 28, height: 28, borderTop: `2px solid ${colors.primary}66`, borderRight: `2px solid ${colors.primary}66` }} />
      <div style={{ position: 'absolute', bottom: 32, left: 32, width: 28, height: 28, borderBottom: `2px solid ${colors.primary}66`, borderLeft: `2px solid ${colors.primary}66` }} />
      <div style={{ position: 'absolute', bottom: 32, right: 32, width: 28, height: 28, borderBottom: `2px solid ${colors.primary}66`, borderRight: `2px solid ${colors.primary}66` }} />
    </AbsoluteFill>
  );
};
