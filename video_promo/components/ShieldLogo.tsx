import React from 'react';
import { useCurrentFrame } from 'remotion';

interface ShieldLogoProps {
  size?: number;
  glowColor?: string;
  isMalicious?: boolean;
}

export const ShieldLogo: React.FC<ShieldLogoProps> = ({
  size = 160,
  glowColor = '#00f0ff',
  isMalicious = false,
}) => {
  const frame = useCurrentFrame();

  const primary = isMalicious ? '#ef4444' : glowColor;
  const secondary = isMalicious ? '#b91c1c' : '#0051ff';

  const ringRotate = frame * 2;
  const ringRotateReverse = -frame * 1.4;
  const pulseScale = 1 + Math.sin(frame * 0.12) * 0.03;

  return (
    <div
      style={{
        position: 'relative',
        width: size,
        height: size,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        transform: `scale(${pulseScale})`,
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
          strokeWidth="1.5"
          strokeDasharray="14,10,35,8"
          opacity="0.6"
        />
        <circle
          cx="100"
          cy="100"
          r="84"
          fill="none"
          stroke={secondary}
          strokeWidth="1"
          strokeDasharray="6,8"
          opacity="0.4"
        />
      </svg>

      {/* Inner Counter-Rotating Hex Ring */}
      <svg
        width={size * 1.1}
        height={size * 1.1}
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
          strokeWidth="2"
          strokeDasharray="30,20"
          opacity="0.7"
        />
      </svg>

      {/* Main Holographic Cyber Shield */}
      <svg
        width={size * 0.75}
        height={size * 0.9}
        viewBox="0 0 100 120"
        fill="none"
        style={{
          filter: `drop-shadow(0 0 24px ${primary}99)`,
        }}
      >
        <defs>
          <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={primary} />
            <stop offset="60%" stopColor={secondary} />
            <stop offset="100%" stopColor="#0a0e17" />
          </linearGradient>
          <linearGradient id="coreGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#ffffff" />
            <stop offset="100%" stopColor={primary} />
          </linearGradient>
        </defs>

        {/* Outer Shield Geometry */}
        <path
          d="M50 5 L90 25 V65 C90 92 50 115 50 115 C50 115 10 92 10 65 V25 L50 5 Z"
          fill="rgba(10, 14, 23, 0.88)"
          stroke="url(#shieldGrad)"
          strokeWidth="3.5"
        />

        {/* Inner Tech Circuit Lines */}
        <path
          d="M50 20 L80 36 V65 C80 84 50 101 50 101 C50 101 20 84 20 65 V36 L50 20 Z"
          fill="rgba(0, 240, 255, 0.06)"
          stroke={primary}
          strokeWidth="1.2"
          strokeDasharray="5,3"
        />

        {/* Central Core / AI Lock Symbol */}
        <polygon
          points="50,38 64,46 64,64 50,72 36,64 36,46"
          fill="url(#coreGrad)"
        />
        <circle cx="50" cy="55" r="4.5" fill="#0a0e17" />

        {/* Top Antenna and Node Accents */}
        <circle cx="50" cy="20" r="2.5" fill={primary} />
        <circle cx="80" cy="36" r="2" fill={primary} />
        <circle cx="20" cy="36" r="2" fill={primary} />
      </svg>
    </div>
  );
};
