import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';

interface Scene1HookProps {
  isVertical?: boolean;
  language?: 'kh' | 'en';
}

export const Scene1Hook: React.FC<Scene1HookProps> = ({
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

  const cameraScale = interpolate(frame, [0, 120], [0.95, 1.05]);

  const hazardSpring = spring({
    fps,
    frame: frame - 10,
    config: { damping: 14, mass: 0.5, stiffness: 100 },
  });

  const headlineSpring = spring({
    fps,
    frame: frame - 22,
    config: { damping: 14, mass: 0.6, stiffness: 90 },
  });

  const cardSpring = spring({
    fps,
    frame: frame - 45,
    config: { damping: 13, mass: 0.5, stiffness: 110 },
  });

  // Ticker counter for simulated threat payloads
  const threatCount = Math.floor(
    interpolate(frame, [0, 120], [14800, 94620], { extrapolateRight: 'clamp' })
  );

  const isKhmer = language === 'kh';

  return (
    <AbsoluteFill
      style={{
        opacity,
        transform: `scale(${cameraScale})`,
        overflow: 'hidden',
      }}
    >
      <CyberBackground glowMode="crimson" gridSpeed={1.8} isVertical={isVertical} />

      {/* Top Threat Telemetry Header */}
      <div
        style={{
          position: 'absolute',
          top: isVertical ? 90 : 50,
          left: 40,
          right: 40,
          display: 'flex',
          flexDirection: isVertical ? 'column' : 'row',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          zIndex: 20,
        }}
      >
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            padding: '8px 16px',
            backgroundColor: 'rgba(239, 68, 68, 0.16)',
            border: '1.5px solid rgba(239, 68, 68, 0.5)',
            borderRadius: 24,
            fontSize: isKhmer ? 13 : 12,
            fontWeight: 800,
            color: '#EF4444',
            letterSpacing: '1px',
          }}
        >
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: '#EF4444',
              boxShadow: '0 0 10px #EF4444',
            }}
          />
          {isKhmer ? 'ការប្រកាសអាសន្នសុវត្ថិភាព TELEGRAM' : 'CRITICAL TELEGRAM ALERT'}
        </div>

        <div
          style={{
            color: '#EF4444',
            fontSize: isKhmer ? 13 : 12.5,
            letterSpacing: '1px',
            backgroundColor: 'rgba(10, 14, 23, 0.7)',
            padding: '6px 14px',
            borderRadius: 14,
            border: '1px solid rgba(239, 68, 68, 0.3)',
          }}
        >
          {isKhmer
            ? `ឯកសារមេរោគរកឃើញ៖ ${threatCount.toLocaleString()} / ២៤ម៉ោង`
            : `MALWARE PAYLOADS DETECTED: ${threatCount.toLocaleString()} / 24H`}
        </div>
      </div>

      {/* Center Content Area */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: isVertical ? '0 40px' : '0 80px',
          textAlign: 'center',
          zIndex: 10,
        }}
      >
        {/* Pulsing Warning Hazard Icon */}
        <div
          style={{
            transform: `scale(${hazardSpring})`,
            width: isVertical ? 96 : 84,
            height: isVertical ? 96 : 84,
            borderRadius: 24,
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            border: '2px solid #EF4444',
            boxShadow: '0 0 35px rgba(239, 68, 68, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: isVertical ? 46 : 40,
            marginBottom: 28,
          }}
        >
          ⚠️
        </div>

        {/* Hook Headline */}
        <div
          style={{
            transform: `scale(${headlineSpring})`,
            maxWidth: isVertical ? 880 : 1200,
          }}
        >
          <div
            style={{
              fontSize: isVertical ? (isKhmer ? 46 : 48) : 56,
              fontWeight: 900,
              lineHeight: 1.25,
              color: '#FFFFFF',
              letterSpacing: isKhmer ? '0px' : '-1.5px',
              textShadow: '0 0 40px rgba(239, 68, 68, 0.55)',
            }}
          >
            {isKhmer ? (
              <>
                ឯកសារគួរឱ្យសង្ស័យតែមួយ
                <br />
                <span style={{ color: '#EF4444' }}>អាចបំផ្លាញ</span>
                <br />
                ប្រព័ន្ធសុវត្ថិភាពរបស់អ្នកទាំងស្រុង។
              </>
            ) : (
              <>
                ONE SUSPICIOUS FILE
                <br />
                <span style={{ color: '#EF4444' }}>CAN COMPROMISE</span>
                <br />
                YOUR ENTIRE SYSTEM.
              </>
            )}
          </div>

          <div
            style={{
              fontSize: isVertical ? (isKhmer ? 20 : 21) : 24,
              color: '#94A3B8',
              marginTop: 18,
              lineHeight: 1.5,
              fontWeight: 500,
            }}
          >
            {isKhmer
              ? 'រាល់ថ្ងៃ ឯកសារបង្កប់មេរោគ PDF, EXE និង Macro រាប់ពាន់កំពុងវាយលុកក្នុង Telegram។'
              : 'Every day, weaponized PDFs, packed EXEs, and macro scripts land in Telegram chats.'}
          </div>
        </div>

        {/* Floating Weaponized Payload Preview Card */}
        <div
          style={{
            transform: `scale(${cardSpring})`,
            opacity: cardSpring,
            marginTop: 36,
            width: '100%',
            maxWidth: isVertical ? 480 : 540,
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            border: '1.5px solid rgba(239, 68, 68, 0.6)',
            borderRadius: 18,
            padding: '16px 20px',
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            boxShadow: '0 12px 35px rgba(0, 0, 0, 0.7), 0 0 25px rgba(239, 68, 68, 0.3)',
          }}
        >
          <div
            style={{
              width: 48,
              height: 48,
              borderRadius: 12,
              backgroundColor: 'rgba(239, 68, 68, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 24,
            }}
          >
            📄
          </div>

          <div style={{ flex: 1, textAlign: 'left' }}>
            <div style={{ fontSize: 16, fontWeight: 800, color: '#FFFFFF', fontFamily: 'Consolas, monospace' }}>
              Invoice_March_Payment.pdf.exe
            </div>
            <div
              style={{
                fontSize: 12,
                color: '#EF4444',
                marginTop: 3,
                fontWeight: 600,
              }}
            >
              {isKhmer
                ? '[!] រកឃើញកន្ទុយឯកសារបង្កប់ EXE គួរឱ្យសង្ស័យ'
                : '[!] HIDDEN EXECUTABLE EXTENSION DETECTED'}
            </div>
          </div>
        </div>

        {/* Punchline */}
        <div
          style={{
            marginTop: 32,
            fontSize: isVertical ? 22 : 24,
            fontWeight: 800,
            color: '#00F0FF',
            letterSpacing: '1px',
            textShadow: '0 0 15px rgba(0, 240, 255, 0.6)',
          }}
        >
          {isKhmer ? 'កុំទាន់បើក បើមិនទាន់បានស្កេន! ➔' : 'DO NOT OPEN UNTIL YOU SCAN. ➔'}
        </div>
      </div>
    </AbsoluteFill>
  );
};