import React from 'react';
import { useCurrentFrame } from 'remotion';

export const CallToAction: React.FC = () => {
  const frame = useCurrentFrame();

  const pulse = Math.sin(frame * 0.15) * 8 + 22;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
      }}
    >
      {/* 3D-styled Glowing Telegram Send Button */}
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 16,
          padding: '18px 48px',
          background: 'linear-gradient(135deg, #00f0ff 0%, #0051ff 100%)',
          borderRadius: 36,
          boxShadow: `0 0 ${pulse}px rgba(0, 240, 255, 0.7), 0 10px 25px rgba(0, 81, 255, 0.4)`,
          border: '1px solid rgba(255, 255, 255, 0.4)',
        }}
      >
        <span style={{ fontSize: 28 }}>✈️</span>
        <span
          style={{
            fontSize: 26,
            fontWeight: 900,
            fontFamily: '"Montserrat", "Inter", sans-serif',
            color: '#0a0e17',
            letterSpacing: '1px',
          }}
        >
          @CyberGuardMalwareBot
        </span>
        <span style={{ color: '#0a0e17', fontSize: 24, fontWeight: 900 }}>→</span>
      </div>

      {/* Futuristic QR Code Component */}
      <div
        style={{
          marginTop: 28,
          position: 'relative',
          padding: 16,
          backgroundColor: 'rgba(17, 24, 39, 0.9)',
          borderRadius: 16,
          border: '1.5px solid rgba(0, 240, 255, 0.4)',
          boxShadow: '0 0 25px rgba(0, 240, 255, 0.25)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 8,
        }}
      >
        {/* SVG Cyber QR Code Visual */}
        <svg width="120" height="120" viewBox="0 0 100 100" fill="none">
          {/* Outer QR Corner Anchors */}
          <rect x="5" y="5" width="28" height="28" rx="4" fill="#00f0ff" />
          <rect x="9" y="9" width="20" height="20" rx="2" fill="#0a0e17" />
          <rect x="13" y="13" width="12" height="12" fill="#00f0ff" />

          <rect x="67" y="5" width="28" height="28" rx="4" fill="#00f0ff" />
          <rect x="71" y="9" width="20" height="20" rx="2" fill="#0a0e17" />
          <rect x="75" y="13" width="12" height="12" fill="#00f0ff" />

          <rect x="5" y="67" width="28" height="28" rx="4" fill="#00f0ff" />
          <rect x="9" y="71" width="20" height="20" rx="2" fill="#0a0e17" />
          <rect x="13" y="75" width="12" height="12" fill="#00f0ff" />

          {/* Random Cyber QR Bit Grid */}
          <rect x="42" y="8" width="6" height="6" fill="#10b981" />
          <rect x="52" y="8" width="6" height="6" fill="#00f0ff" />
          <rect x="42" y="18" width="6" height="6" fill="#00f0ff" />
          <rect x="52" y="24" width="6" height="6" fill="#10b981" />
          <rect x="10" y="42" width="6" height="6" fill="#00f0ff" />
          <rect x="22" y="48" width="6" height="6" fill="#00f0ff" />
          <rect x="38" y="38" width="8" height="8" fill="#00f0ff" />
          <rect x="48" y="48" width="8" height="8" fill="#10b981" />
          <rect x="58" y="38" width="8" height="8" fill="#00f0ff" />
          <rect x="74" y="44" width="6" height="6" fill="#00f0ff" />
          <rect x="84" y="52" width="6" height="6" fill="#10b981" />
          <rect x="44" y="68" width="6" height="6" fill="#10b981" />
          <rect x="54" y="74" width="6" height="6" fill="#00f0ff" />
          <rect x="66" y="82" width="6" height="6" fill="#00f0ff" />
          <rect x="80" y="74" width="6" height="6" fill="#10b981" />
        </svg>

        <span style={{ fontSize: 10, color: '#00f0ff', letterSpacing: '2px', fontFamily: 'Consolas, monospace' }}>
          SCAN OR SEARCH ON TELEGRAM
        </span>
      </div>

      {/* Feature Badges */}
      <div
        style={{
          marginTop: 24,
          display: 'flex',
          gap: 24,
          fontSize: 13,
          color: '#9ca3af',
          fontFamily: 'Consolas, monospace',
          letterSpacing: '1px',
        }}
      >
        <span>✔ ALWAYS FREE</span>
        <span>✔ ZERO-TRUST PRIVACY</span>
        <span>✔ 24/7 SERVERLESS EDGE</span>
      </div>
    </div>
  );
};
