import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { TelegramFootage } from '../components/TelegramFootage';
import { TelegramCallouts } from '../components/TelegramCallouts';

interface Scene3DemoProps {
  isVertical?: boolean;
  useRealFootage?: boolean;
  language?: 'kh' | 'en';
}

export const Scene3Demo: React.FC<Scene3DemoProps> = ({
  isVertical = true,
  useRealFootage = false,
  language = 'kh',
}) => {
  const frame = useCurrentFrame();

  // Scene fade in / out (total 270 frames)
  const opacity = interpolate(frame, [0, 15, 255, 270], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
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
      <CyberBackground glowMode="cyan" gridSpeed={1.0} isVertical={isVertical} />

      {/* Top HUD Telemetry Banner */}
      <div
        style={{
          position: 'absolute',
          top: isVertical ? 70 : 40,
          left: 40,
          right: 40,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          zIndex: 40,
        }}
      >
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            padding: '6px 16px',
            backgroundColor: 'rgba(0, 240, 255, 0.12)',
            border: '1.5px solid rgba(0, 240, 255, 0.4)',
            borderRadius: 20,
            fontSize: isKhmer ? 12 : 11.5,
            fontWeight: 800,
            color: '#00F0FF',
            letterSpacing: '0.5px',
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              backgroundColor: '#10B981',
              boxShadow: '0 0 8px #10B981',
            }}
          />
          {isKhmer ? 'ការបង្ហាញការប្រើប្រាស់ផ្ទាល់លើ TELEGRAM' : 'INTERACTIVE TELEGRAM BOT DEMO'}
        </div>

        <div
          style={{
            color: '#94A3B8',
            fontSize: 11.5,
            letterSpacing: '0.5px',
          }}
        >
          SESSION: <span style={{ color: '#00F0FF' }}>{isKhmer ? 'សុវត្ថិភាពខ្ពស់' : 'EDGE-ISOLATED'}</span>
        </div>
      </div>

      {/* Main Telegram Smartphone Showcase */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 20,
          paddingTop: isVertical ? 40 : 0,
        }}
      >
        <TelegramFootage useRealFootage={useRealFootage} language={language} />
      </div>

      {/* Dynamic Animated Callouts */}
      <TelegramCallouts language={language} />

      {/* Bottom Status Ticker */}
      <div
        style={{
          position: 'absolute',
          bottom: isVertical ? 120 : 40,
          left: 0,
          right: 0,
          textAlign: 'center',
          zIndex: 40,
        }}
      >
        <span
          style={{
            fontSize: isKhmer ? 12 : 11.5,
            color: '#64748B',
            letterSpacing: '0.5px',
            backgroundColor: 'rgba(10, 14, 23, 0.8)',
            padding: '6px 18px',
            borderRadius: 16,
            border: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          {isKhmer
            ? 'ប្រព័ន្ធស្កេនលើ Edge Serverless • គ្មានការរក្សាទុកឯកសារ • សុវត្ថិភាព ១០០%'
            : 'SECURE CLUSTER • IN-MEMORY STREAMING • NO PERSISTENT LOGS'}
        </span>
      </div>
    </AbsoluteFill>
  );
};