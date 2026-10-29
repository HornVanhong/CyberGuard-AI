import React from 'react';
import { interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { CyberGuardLogo } from './CyberGuardLogo';

interface CallToActionProps {
  isVertical?: boolean;
  language?: 'kh' | 'en';
}

export const CallToAction: React.FC<CallToActionProps> = ({
  isVertical = true,
  language = 'kh',
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const isKhmer = language === 'kh';

  const logoSpring = spring({
    fps,
    frame,
    config: { damping: 14, mass: 0.6, stiffness: 95 },
  });

  const cardSpring = spring({
    fps,
    frame: frame - 18,
    config: { damping: 13, mass: 0.5, stiffness: 100 },
  });

  const pulse = 1 + Math.sin(frame * 0.1) * 0.025;
  const glow = 15 + Math.sin(frame * 0.12) * 8;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        width: '100%',
        maxWidth: isVertical ? 860 : 1200,
        margin: '0 auto',
        padding: isVertical ? '0 32px' : '0 40px',
        zIndex: 20,
      }}
    >
      {/* Center Shield Logo with Energy Aura */}
      <div
        style={{
          transform: `scale(${logoSpring})`,
          marginBottom: isVertical ? 20 : 18,
        }}
      >
        <CyberGuardLogo size={isVertical ? 250 : 180} glowColor="#00F0FF" />
      </div>

      {/* Main Punchy Typography */}
      <div
        style={{
          transform: `scale(${cardSpring})`,
          opacity: interpolate(frame, [10, 25], [0, 1], {
            extrapolateLeft: 'clamp',
            extrapolateRight: 'clamp',
          }),
        }}
      >
        <div
          style={{
            fontSize: isVertical ? (isKhmer ? 42 : 46) : 52,
            fontWeight: 900,
            color: '#FFFFFF',
            letterSpacing: isKhmer ? '0px' : '-1px',
            lineHeight: 1.2,
            textShadow: '0 0 30px rgba(0, 240, 255, 0.45)',
          }}
        >
          {isKhmer ? 'ការពារសុវត្ថិភាពឌីជីថលរបស់អ្នក' : 'PROTECT YOUR DIGITAL LIFE'}
        </div>

        <div
          style={{
            fontSize: isVertical ? (isKhmer ? 18 : 20) : 22,
            color: '#94A3B8',
            marginTop: 10,
            marginBottom: isVertical ? 28 : 24,
            fontWeight: 500,
          }}
        >
          {isKhmer
            ? 'ស្កេនឯកសារគួរឱ្យសង្ស័យត្រឹមប៉ុន្មានវិនាទី — ផ្ទាល់លើ Telegram។'
            : 'Scan suspicious files in seconds — right inside Telegram.'}
        </div>
      </div>

      {/* 3D Hero Action Card */}
      <div
        style={{
          transform: `scale(${cardSpring * pulse})`,
          opacity: cardSpring,
          width: '100%',
          maxWidth: isVertical ? 640 : 700,
          backgroundColor: 'rgba(15, 23, 42, 0.92)',
          border: '2px solid #00F0FF',
          borderRadius: 24,
          padding: isVertical ? '28px 24px' : '28px 36px',
          boxShadow: `0 20px 60px rgba(0, 0, 0, 0.8), 0 0 ${glow}px rgba(0, 240, 255, 0.4)`,
          display: 'flex',
          flexDirection: isVertical ? 'column' : 'row',
          alignItems: 'center',
          gap: isVertical ? 20 : 28,
        }}
      >
        {/* Holographic QR Code Box */}
        <div
          style={{
            position: 'relative',
            padding: 12,
            backgroundColor: '#0A0E17',
            borderRadius: 18,
            border: '1.5px solid rgba(0, 240, 255, 0.5)',
            boxShadow: '0 0 20px rgba(0, 240, 255, 0.25)',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
          }}
        >
          {/* High-tech QR Code Pattern Representation */}
          <svg width="130" height="130" viewBox="0 0 100 100">
            <rect width="100" height="100" fill="#0A0E17" />
            {/* Corner position markers */}
            <rect x="5" y="5" width="26" height="26" fill="none" stroke="#00F0FF" strokeWidth="4" rx="3" />
            <rect x="11" y="11" width="14" height="14" fill="#00F0FF" rx="2" />

            <rect x="69" y="5" width="26" height="26" fill="none" stroke="#00F0FF" strokeWidth="4" rx="3" />
            <rect x="75" y="11" width="14" height="14" fill="#00F0FF" rx="2" />

            <rect x="5" y="69" width="26" height="26" fill="none" stroke="#00F0FF" strokeWidth="4" rx="3" />
            <rect x="11" y="75" width="14" height="14" fill="#00F0FF" rx="2" />

            {/* Matrix Data Blocks */}
            <rect x="36" y="8" width="6" height="6" fill="#10B981" />
            <rect x="46" y="8" width="14" height="6" fill="#00F0FF" />
            <rect x="36" y="18" width="10" height="6" fill="#00F0FF" />
            <rect x="52" y="18" width="8" height="6" fill="#10B981" />
            <rect x="10" y="38" width="14" height="6" fill="#00F0FF" />
            <rect x="28" y="38" width="8" height="12" fill="#38BDF8" />
            <rect x="40" y="32" width="20" height="20" fill="#0051FF" rx="4" />
            {/* Center Logo in QR */}
            <circle cx="50" cy="42" r="6" fill="#00F0FF" />
            <rect x="68" y="38" width="10" height="8" fill="#10B981" />
            <rect x="82" y="38" width="10" height="14" fill="#00F0FF" />
            <rect x="8" y="54" width="8" height="8" fill="#10B981" />
            <rect x="22" y="54" width="12" height="6" fill="#00F0FF" />
            <rect x="42" y="60" width="16" height="8" fill="#00F0FF" />
            <rect x="64" y="54" width="12" height="12" fill="#38BDF8" />
            <rect x="80" y="58" width="12" height="6" fill="#10B981" />
            <rect x="38" y="76" width="12" height="14" fill="#10B981" />
            <rect x="56" y="74" width="14" height="8" fill="#00F0FF" />
            <rect x="76" y="78" width="16" height="12" fill="#00F0FF" />
          </svg>

          <span
            style={{
              fontSize: 10,
              fontFamily: 'Consolas, monospace',
              color: '#00F0FF',
              fontWeight: 800,
              letterSpacing: '1px',
              marginTop: 6,
            }}
          >
            t.me/SmartPTbot
          </span>
        </div>

        {/* Info & Telegram Button */}
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            alignItems: isVertical ? 'center' : 'flex-start',
            textAlign: isVertical ? 'center' : 'left',
          }}
        >
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              backgroundColor: 'rgba(0, 240, 255, 0.15)',
              padding: '4px 12px',
              borderRadius: 20,
              fontSize: 12,
              fontWeight: 800,
              color: '#00F0FF',
              marginBottom: 8,
            }}
          >
            {isKhmer ? 'ជំនួយការលើ TELEGRAM' : 'TELEGRAM ASSISTANT'}
          </div>

          <div
            style={{
              fontSize: isVertical ? 28 : 30,
              fontWeight: 900,
              color: '#FFFFFF',
              letterSpacing: '-0.5px',
              fontFamily: 'Consolas, monospace',
            }}
          >
            @SmartPTbot
          </div>

          <div
            style={{
              fontSize: isKhmer ? 12 : 13,
              color: '#10B981',
              fontWeight: 600,
              marginTop: 4,
              marginBottom: 16,
            }}
          >
            {isKhmer
              ? 'ឥតគិតថ្លៃ ១០០% • Zero-Trust • ដំណើរការ ២៤/៧'
              : '100% Free • Zero-Trust Edge • 24/7 Serverless'}
          </div>

          {/* Telegram Send Button */}
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
              background: 'linear-gradient(135deg, #00F0FF, #0051FF)',
              color: '#0A0E17',
              padding: isKhmer ? '10px 24px' : '12px 28px',
              borderRadius: 14,
              fontSize: isKhmer ? 14 : 15,
              fontWeight: 900,
              letterSpacing: '0.3px',
              boxShadow: '0 6px 20px rgba(0, 240, 255, 0.45)',
            }}
          >
            {/* Telegram Plane SVG */}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
              <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
            </svg>
            {isKhmer ? 'ចាប់ផ្តើមប្រើ BOT លើ TELEGRAM' : 'START BOT IN TELEGRAM'}
          </div>
        </div>
      </div>

      {/* Powered by Edge & Gemini Footer */}
      <div
        style={{
          marginTop: isVertical ? 24 : 20,
          fontSize: 12,
          color: '#64748B',
          letterSpacing: '0.5px',
          fontWeight: 600,
        }}
      >
        {isKhmer
          ? 'CLOUDFLARE EDGE • GOOGLE GEMINI AI • 12 ម៉ាស៊ីនស្កេនស្របគ្នា'
          : 'CLOUDFLARE EDGE WORKERS • GOOGLE GEMINI AI • 12 SCANNING ENGINES'}
      </div>
    </div>
  );
};