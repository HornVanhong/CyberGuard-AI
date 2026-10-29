import React from 'react';
import { interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';

interface GlitchTitleProps {
  text: string;
  fontSize?: number;
  color?: string;
  glowColor?: string;
  delay?: number;
  letterSpacing?: number;
  isGlitching?: boolean;
}

export const GlitchTitle: React.FC<GlitchTitleProps> = ({
  text,
  fontSize = 56,
  color = '#ffffff',
  glowColor = '#ef4444',
  delay = 0,
  letterSpacing = 2,
  isGlitching = true,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const adjustedFrame = Math.max(0, frame - delay);

  // Smooth Spring entrance with requested physics
  const scale = spring({
    fps,
    frame: adjustedFrame,
    config: { damping: 15, mass: 0.5, stiffness: 100 },
  });

  const opacity = interpolate(adjustedFrame, [0, 15], [0, 1], {
    extrapolateRight: 'clamp',
  });

  // Text wipe progression (0% to 100%)
  const wipeProgress = interpolate(adjustedFrame, [5, 40], [0, 100], {
    extrapolateRight: 'clamp',
  });

  // Glitch effect triggers periodically
  const glitchTrigger = isGlitching && (frame % 24 < 3 || frame % 40 === 0);
  const glitchOffsetX = glitchTrigger ? Math.sin(frame * 5) * 8 : 0;
  const glitchOffsetY = glitchTrigger ? Math.cos(frame * 4) * 4 : 0;

  return (
    <div
      style={{
        display: 'inline-block',
        position: 'relative',
        opacity,
        transform: `scale(${scale})`,
        textAlign: 'center',
      }}
    >
      {/* Glitch chromatic split layer 1 (Cyan) */}
      {glitchTrigger && (
        <div
          style={{
            position: 'absolute',
            top: glitchOffsetY - 2,
            left: glitchOffsetX - 4,
            fontSize,
            fontWeight: 900,
            letterSpacing: `${letterSpacing}px`,
            fontFamily: '"Montserrat", "Inter", -apple-system, sans-serif',
            color: '#00f0ff',
            opacity: 0.8,
            userSelect: 'none',
            pointerEvents: 'none',
            clipPath: `polygon(0 0, ${wipeProgress}% 0, ${wipeProgress}% 100%, 0 100%)`,
          }}
        >
          {text}
        </div>
      )}

      {/* Glitch chromatic split layer 2 (Red) */}
      {glitchTrigger && (
        <div
          style={{
            position: 'absolute',
            top: glitchOffsetY + 2,
            left: glitchOffsetX + 4,
            fontSize,
            fontWeight: 900,
            letterSpacing: `${letterSpacing}px`,
            fontFamily: '"Montserrat", "Inter", -apple-system, sans-serif',
            color: '#ef4444',
            opacity: 0.8,
            userSelect: 'none',
            pointerEvents: 'none',
            clipPath: `polygon(0 0, ${wipeProgress}% 0, ${wipeProgress}% 100%, 0 100%)`,
          }}
        >
          {text}
        </div>
      )}

      {/* Main sharp text with wipe clip */}
      <div
        style={{
          fontSize,
          fontWeight: 900,
          letterSpacing: `${letterSpacing}px`,
          fontFamily: '"Montserrat", "Inter", -apple-system, sans-serif',
          color,
          textShadow: `0 0 20px ${glowColor}aa, 0 0 45px ${glowColor}55`,
          clipPath: `polygon(0 0, ${wipeProgress}% 0, ${wipeProgress}% 100%, 0 100%)`,
        }}
      >
        {text}
      </div>
    </div>
  );
};
