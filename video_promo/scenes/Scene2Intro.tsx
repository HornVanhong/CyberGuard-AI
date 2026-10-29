import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { ShieldLogo } from '../components/ShieldLogo';

export const Scene2Intro: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Scene transition
  const sceneOpacity = interpolate(frame, [0, 15, 165, 180], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const cameraScale = interpolate(frame, [0, 180], [0.95, 1.05]);

  // Shield logo burst spring
  const shieldSpring = spring({
    fps,
    frame: frame - 10,
    config: { damping: 15, mass: 0.5, stiffness: 100 },
  });

  // Title spring
  const titleSpring = spring({
    fps,
    frame: frame - 30,
    config: { damping: 15, mass: 0.5, stiffness: 100 },
  });

  // Badges spring
  const badgesSpring = spring({
    fps,
    frame: frame - 60,
    config: { damping: 14, mass: 0.5, stiffness: 90 },
  });

  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity,
        transform: `scale(${cameraScale})`,
      }}
    >
      <CyberBackground glowMode="cyan" />

      {/* Main Presentation Container */}
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
        {/* Shield Logo Burst */}
        <div style={{ transform: `scale(${shieldSpring})`, marginBottom: 28 }}>
          <ShieldLogo size={180} glowColor="#00f0ff" />
        </div>

        {/* Title & Brand Announcement */}
        <div style={{ transform: `scale(${titleSpring})` }}>
          <div
            style={{
              fontSize: 16,
              fontWeight: 800,
              color: '#00f0ff',
              fontFamily: 'Consolas, monospace',
              letterSpacing: '5px',
              textTransform: 'uppercase',
              marginBottom: 10,
            }}
          >
            NEXT-GEN TELEGRAM CYBER DEFENSE
          </div>

          <div
            style={{
              fontSize: 56,
              fontWeight: 900,
              letterSpacing: '-0.5px',
              fontFamily: '"Montserrat", "Inter", sans-serif',
              background: 'linear-gradient(180deg, #ffffff 0%, #dcfce7 40%, #00f0ff 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              textShadow: '0 0 35px rgba(0, 240, 255, 0.6)',
              lineHeight: 1.15,
            }}
          >
            Meet CyberGuard AI
          </div>

          <div
            style={{
              fontSize: 24,
              fontWeight: 700,
              color: '#e2e8f0',
              marginTop: 12,
              letterSpacing: '1px',
            }}
          >
            Your 24/7 Telegram Cybersecurity Assistant
          </div>

          <div
            style={{
              fontSize: 16,
              color: '#38bdf8',
              fontFamily: 'Consolas, monospace',
              marginTop: 10,
              letterSpacing: '2px',
            }}
          >
            Cloudflare Edge Gateway • Google Gemini AI • Deep Malware Analysis
          </div>
        </div>

        {/* Feature Pills */}
        <div
          style={{
            transform: `scale(${badgesSpring})`,
            display: 'flex',
            gap: 16,
            marginTop: 34,
          }}
        >
          <div style={{ background: 'rgba(0, 240, 255, 0.12)', border: '1px solid rgba(0, 240, 255, 0.4)', padding: '8px 20px', borderRadius: 20, color: '#00f0ff', fontSize: 13, fontWeight: 700, fontFamily: 'Consolas, monospace' }}>
            ⚡ 12 HEAVY-DUTY ENGINES
          </div>
          <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.4)', padding: '8px 20px', borderRadius: 20, color: '#10b981', fontSize: 13, fontWeight: 700, fontFamily: 'Consolas, monospace' }}>
            🔒 ZERO HOST PERSISTENCE
          </div>
          <div style={{ background: 'rgba(139, 92, 246, 0.12)', border: '1px solid rgba(139, 92, 246, 0.4)', padding: '8px 20px', borderRadius: 20, color: '#c4b5fd', fontSize: 13, fontWeight: 700, fontFamily: 'Consolas, monospace' }}>
            🌐 BILINGUAL EN & ភាសាខ្មែរ
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};
