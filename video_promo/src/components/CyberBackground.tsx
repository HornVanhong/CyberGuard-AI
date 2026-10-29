import React, { useMemo } from 'react';
import { AbsoluteFill, useCurrentFrame } from 'remotion';

interface CyberBackgroundProps {
  glowMode?: 'cyan' | 'crimson' | 'emerald';
  gridSpeed?: number;
  isVertical?: boolean;
}

export const CyberBackground: React.FC<CyberBackgroundProps> = ({
  glowMode = 'cyan',
  gridSpeed = 1.2,
  isVertical = true,
}) => {
  const frame = useCurrentFrame();

  const colors = {
    cyan: { primary: '#00F0FF', secondary: '#0051FF', ambient: 'rgba(0, 240, 255, 0.14)' },
    crimson: { primary: '#EF4444', secondary: '#991B1B', ambient: 'rgba(239, 68, 68, 0.16)' },
    emerald: { primary: '#10B981', secondary: '#047857', ambient: 'rgba(16, 185, 129, 0.14)' },
  }[glowMode];

  // Floating particles
  const particles = useMemo(() => {
    const glyphs = ['0x4A', '0x9F', 'TCP', 'TLS', 'YARA', 'SHA', 'SIG', 'PE', 'CVE', 'HEX', '0', '1'];
    return Array.from({ length: 36 }).map((_, i) => ({
      id: i,
      char: glyphs[i % glyphs.length],
      x: ((i * 137.5) % 94) + 3,
      baseY: ((i * 79.3) % 94) + 3,
      speed: 0.1 + ((i % 5) * 0.05),
      size: i % 4 === 0 ? (isVertical ? 14 : 11) : 3 + (i % 3) * 2,
      isText: i % 3 === 0,
      opacity: 0.12 + ((i % 4) * 0.1),
    }));
  }, [isVertical]);

  const pulse = Math.sin(frame * 0.08) * 0.18 + 0.82;
  const gridOffsetY = (frame * gridSpeed) % 40;

  return (
    <AbsoluteFill
      style={{
        backgroundColor: '#0A0E17',
        overflow: 'hidden',
        pointerEvents: 'none',
      }}
    >
      {/* Deep Navy Radial Background */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: `radial-gradient(circle at 50% 38%, ${colors.secondary}22 0%, #0A0E17 80%)`,
        }}
      />

      {/* Primary Ambient Glow Sphere */}
      <div
        style={{
          position: 'absolute',
          top: isVertical ? '15%' : '20%',
          left: '15%',
          width: isVertical ? 650 : 800,
          height: isVertical ? 650 : 800,
          borderRadius: '50%',
          background: `radial-gradient(circle, ${colors.primary}1a 0%, transparent 70%)`,
          filter: 'blur(100px)',
          transform: `scale(${pulse})`,
        }}
      />

      {/* Secondary Ambient Glow Sphere */}
      <div
        style={{
          position: 'absolute',
          bottom: isVertical ? '12%' : '15%',
          right: '15%',
          width: isVertical ? 680 : 850,
          height: isVertical ? 680 : 850,
          borderRadius: '50%',
          background: `radial-gradient(circle, ${colors.secondary}24 0%, transparent 70%)`,
          filter: 'blur(110px)',
          transform: `scale(${1.9 - pulse})`,
        }}
      />

      {/* Perspective / Cyber Grid */}
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

      {/* Scanning Laser Line */}
      <div
        style={{
          position: 'absolute',
          left: 0,
          right: 0,
          height: 2,
          top: `${((frame * 4) % (isVertical ? 2000 : 1150)) - 50}px`,
          background: `linear-gradient(90deg, transparent 0%, ${colors.primary}99 50%, transparent 100%)`,
          boxShadow: `0 0 16px ${colors.primary}`,
          opacity: 0.5,
        }}
      />

      {/* Floating Particles */}
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
          opacity: 0.55,
          pointerEvents: 'none',
        }}
      />

      {/* Vignette */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: 'radial-gradient(ellipse at center, transparent 40%, rgba(10, 14, 23, 0.88) 100%)',
        }}
      />

      {/* Safe Area Corner HUD Accents */}
      <div style={{ position: 'absolute', top: 40, left: 40, width: 24, height: 24, borderTop: `2px solid ${colors.primary}66`, borderLeft: `2px solid ${colors.primary}66` }} />
      <div style={{ position: 'absolute', top: 40, right: 40, width: 24, height: 24, borderTop: `2px solid ${colors.primary}66`, borderRight: `2px solid ${colors.primary}66` }} />
      <div style={{ position: 'absolute', bottom: 40, left: 40, width: 24, height: 24, borderBottom: `2px solid ${colors.primary}66`, borderLeft: `2px solid ${colors.primary}66` }} />
      <div style={{ position: 'absolute', bottom: 40, right: 40, width: 24, height: 24, borderBottom: `2px solid ${colors.primary}66`, borderRight: `2px solid ${colors.primary}66` }} />
    </AbsoluteFill>
  );
};
