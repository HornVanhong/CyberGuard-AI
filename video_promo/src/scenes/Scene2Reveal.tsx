import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { CyberGuardLogo } from '../components/CyberGuardLogo';

interface Scene2RevealProps {
  isVertical?: boolean;
  language?: 'kh' | 'en';
}

export const Scene2Reveal: React.FC<Scene2RevealProps> = ({
  isVertical = true,
  language = 'kh',
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Scene fade in / out
  const opacity = interpolate(frame, [0, 15, 105, 120], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const logoSpring = spring({
    fps,
    frame: frame - 5,
    config: { damping: 13, mass: 0.6, stiffness: 90 },
  });

  const textSpring = spring({
    fps,
    frame: frame - 25,
    config: { damping: 14, mass: 0.5, stiffness: 100 },
  });

  const badgesSpring = spring({
    fps,
    frame: frame - 45,
    config: { damping: 13, mass: 0.5, stiffness: 110 },
  });

  // Shockwave ring expansion
  const shockwaveScale = interpolate(frame, [0, 45], [0.2, 3.2], {
    extrapolateRight: 'clamp',
  });
  const shockwaveOpacity = interpolate(frame, [0, 15, 45], [0.8, 0.5, 0], {
    extrapolateRight: 'clamp',
  });

  const isKhmer = language === 'kh';

  return (
    <AbsoluteFill
      style={{
        opacity,
        overflow: 'hidden',
      }}
    >
      <CyberBackground glowMode="cyan" gridSpeed={1.4} isVertical={isVertical} />

      {/* Center Shockwave Expansion Ring */}
      <div
        style={{
          position: 'absolute',
          top: '38%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          width: 320,
          height: 320,
          borderRadius: '50%',
          border: '3px solid #00F0FF',
          boxShadow: '0 0 40px #00F0FF',
          transformOrigin: 'center center',
          scale: `${shockwaveScale}`,
          opacity: shockwaveOpacity,
          pointerEvents: 'none',
        }}
      />

      {/* Main Center Content */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: isVertical ? '0 36px' : '0 80px',
          textAlign: 'center',
          zIndex: 10,
        }}
      >
        {/* Category Pill Tag */}
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            padding: '6px 18px',
            backgroundColor: 'rgba(0, 240, 255, 0.14)',
            border: '1.5px solid rgba(0, 240, 255, 0.45)',
            borderRadius: 20,
            fontSize: isKhmer ? 13 : 12,
            fontWeight: 800,
            color: '#00F0FF',
            letterSpacing: '1px',
            marginBottom: isVertical ? 24 : 20,
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              backgroundColor: '#00F0FF',
              boxShadow: '0 0 8px #00F0FF',
            }}
          />
          {isKhmer ? 'ប្រព័ន្ធការពារជំនាន់ថ្មីលើ TELEGRAM' : 'NEXT-GEN DEFENSE ON TELEGRAM'}
        </div>

        {/* CyberGuard Shield Hero Mark */}
        <div
          style={{
            transform: `scale(${logoSpring})`,
            marginBottom: isVertical ? 32 : 22,
          }}
        >
          <CyberGuardLogo size={isVertical ? 340 : 210} glowColor="#00F0FF" />
        </div>

        {/* Product Brand Headline */}
        <div
          style={{
            transform: `scale(${textSpring})`,
            maxWidth: isVertical ? 920 : 1200,
          }}
        >
          <div
            style={{
              fontSize: isVertical ? 68 : 64,
              fontWeight: 900,
              color: '#FFFFFF',
              letterSpacing: '-2px',
              lineHeight: 1.08,
              textShadow: '0 0 50px rgba(0, 240, 255, 0.5)',
            }}
          >
            CYBERGUARD AI
          </div>

          <div
            style={{
              fontSize: isVertical ? (isKhmer ? 24 : 25) : 26,
              color: '#00F0FF',
              fontWeight: 700,
              letterSpacing: '0.3px',
              marginTop: 12,
            }}
          >
            {isKhmer
              ? 'ជំនួយការស្កេនមេរោគ និងការពារសុវត្ថិភាពលើ Telegram'
              : 'Telegram Malware Scanner & Security Assistant'}
          </div>

          <div
            style={{
              fontSize: isVertical ? (isKhmer ? 18 : 19) : 19,
              color: '#94A3B8',
              marginTop: 16,
              maxWidth: isVertical ? 760 : 800,
              margin: '16px auto 0',
              lineHeight: 1.55,
            }}
          >
            {isKhmer
              ? 'ស្កេនមេរោគជាមួយម៉ាស៊ីនវិភាគកម្រិតខ្ពស់ Decompile កូដ និងពន្យល់ហានិភ័យដោយ Google Gemini AI ផ្ទាល់ក្នុង Telegram។'
              : 'Real-time multi-engine malware inspection, decompiler integration, and AI threat explanations right inside your chat.'}
          </div>
        </div>

        {/* 3 Pillar Tech Badges */}
        <div
          style={{
            transform: `scale(${badgesSpring})`,
            opacity: badgesSpring,
            display: 'flex',
            flexWrap: 'wrap',
            justifyContent: 'center',
            gap: 12,
            marginTop: isVertical ? 32 : 28,
            maxWidth: isVertical ? 760 : 960,
          }}
        >
          <div
            style={{
              backgroundColor: 'rgba(15, 23, 42, 0.9)',
              border: '1.5px solid rgba(0, 240, 255, 0.4)',
              borderRadius: 14,
              padding: '10px 18px',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 13,
              fontWeight: 700,
              color: '#F4F7FB',
            }}
          >
            <span>⚡</span> Cloudflare Edge Gateway
          </div>

          <div
            style={{
              backgroundColor: 'rgba(15, 23, 42, 0.9)',
              border: '1.5px solid rgba(139, 92, 246, 0.5)',
              borderRadius: 14,
              padding: '10px 18px',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 13,
              fontWeight: 700,
              color: '#F4F7FB',
            }}
          >
            <span>✨</span> {isKhmer ? 'Google Gemini AI វិភាគហានិភ័យ' : 'Google Gemini Threat AI'}
          </div>

          <div
            style={{
              backgroundColor: 'rgba(15, 23, 42, 0.9)',
              border: '1.5px solid rgba(16, 185, 129, 0.5)',
              borderRadius: 14,
              padding: '10px 18px',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 13,
              fontWeight: 700,
              color: '#F4F7FB',
            }}
          >
            <span>🛡️</span> {isKhmer ? 'ម៉ាស៊ីនស្កេនស្របគ្នា ១២ កម្រិត' : '12 Parallel Analysis Engines'}
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};