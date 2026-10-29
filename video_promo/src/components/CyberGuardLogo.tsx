import React from 'react';
import { Img, staticFile, useCurrentFrame } from 'remotion';

interface CyberGuardLogoProps {
  size?: number;
  glowColor?: string;
  isMalicious?: boolean;
}

export const CyberGuardLogo: React.FC<CyberGuardLogoProps> = ({
  size = 200,
  glowColor = '#00F0FF',
  isMalicious = false,
}) => {
  const frame = useCurrentFrame();

  const primary = isMalicious ? '#EF4444' : glowColor;
  const secondary = isMalicious ? '#991B1B' : '#0051FF';

  const ringRotate = frame * 2;
  const ringRotateReverse = -frame * 1.5;
  const pulse = 1 + Math.sin(frame * 0.12) * 0.035;

  return (
    <div
      style={{
        position: 'relative',
        width: size,
        height: size,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        transform: `scale(${pulse})`,
      }}
    >
      {/* Outer Rotating Energy Ring */}
      <svg
        width={size * 1.3}
        height={size * 1.3}
        viewBox="0 0 200 200"
        style={{
          position: 'absolute',
          transform: `rotate(${ringRotate}deg)`,
          pointerEvents: 'none',
        }}
      >
        <circle
          cx="100"
          cy="100"
          r="92"
          fill="none"
          stroke={primary}
          strokeWidth="1.8"
          strokeDasharray="14,10,35,8"
          opacity="0.75"
        />
        <circle
          cx="100"
          cy="100"
          r="84"
          fill="none"
          stroke={secondary}
          strokeWidth="1.2"
          strokeDasharray="6,8"
          opacity="0.55"
        />
      </svg>

      {/* Inner Counter-Rotating Hex Ring */}
      <svg
        width={size * 1.12}
        height={size * 1.12}
        viewBox="0 0 160 160"
        style={{
          position: 'absolute',
          transform: `rotate(${ringRotateReverse}deg)`,
          pointerEvents: 'none',
        }}
      >
        <circle
          cx="80"
          cy="80"
          r="74"
          fill="none"
          stroke={primary}
          strokeWidth="2.2"
          strokeDasharray="30,20"
          opacity="0.85"
        />
      </svg>

      {/* Circular CyberGuard Bot Mascot Emblem */}
      <div
        style={{
          position: 'relative',
          width: size * 0.86,
          height: size * 0.86,
          borderRadius: '50%',
          overflow: 'hidden',
          backgroundColor: '#0A0E17',
          border: `2.5px solid ${primary}`,
          boxShadow: `0 0 30px ${primary}99, inset 0 0 15px ${primary}44`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 5,
        }}
      >
        <Img
          src={staticFile('logo.jpg')}
          alt="CyberGuard AI Telegram Bot Logo"
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
          }}
        />

        {/* Ambient Gloss Highlight */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(135deg, rgba(255,255,255,0.2) 0%, transparent 50%, rgba(0,240,255,0.15) 100%)',
            pointerEvents: 'none',
            borderRadius: '50%',
          }}
        />
      </div>
    </div>
  );
};