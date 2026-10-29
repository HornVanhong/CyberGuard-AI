import React from 'react';
import { spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { VERIFIED_ENGINES } from '../data/storyboard';

interface EngineGridProps {
  isVertical?: boolean;
  language?: 'kh' | 'en';
}

export const EngineGrid: React.FC<EngineGridProps> = ({
  isVertical = true,
  language = 'kh',
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const isKhmer = language === 'kh';

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: isVertical ? 'repeat(2, 1fr)' : 'repeat(4, 1fr)',
        gap: isVertical ? '16px' : '20px',
        width: '100%',
        maxWidth: isVertical ? 920 : 1600,
        margin: '0 auto',
      }}
    >
      {VERIFIED_ENGINES.map((engine, idx) => {
        // Staggered spring entrance (deterministic timing, no delayRender)
        const delay = idx * 6;
        const cardSpring = spring({
          fps,
          frame: frame - delay,
          config: { damping: 13, mass: 0.5, stiffness: 110 },
        });

        const pulse = 1 + Math.sin((frame + idx * 10) * 0.1) * 0.02;

        return (
          <div
            key={engine.name}
            style={{
              transform: `scale(${cardSpring * pulse}) translateY(${(1 - cardSpring) * 35}px)`,
              opacity: cardSpring,
              backgroundColor: 'rgba(15, 23, 42, 0.85)',
              border: `1.5px solid ${engine.color}44`,
              borderRadius: 18,
              padding: isVertical ? '20px 18px' : '22px 20px',
              boxShadow: `0 8px 30px rgba(0, 0, 0, 0.5), 0 0 20px ${engine.color}22`,
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            {/* Top accent bar */}
            <div
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                height: 3,
                background: `linear-gradient(90deg, ${engine.color}, transparent)`,
              }}
            />

            {/* Header: Icon + Status */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 12,
              }}
            >
              <div
                style={{
                  width: isVertical ? 42 : 46,
                  height: isVertical ? 42 : 46,
                  borderRadius: 12,
                  backgroundColor: `${engine.color}20`,
                  border: `1px solid ${engine.color}55`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: isVertical ? 22 : 24,
                }}
              >
                {engine.icon}
              </div>

              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 5,
                  padding: '3px 8px',
                  borderRadius: 20,
                  backgroundColor: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.4)',
                }}
              >
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    backgroundColor: '#10B981',
                    boxShadow: '0 0 6px #10B981',
                  }}
                />
                <span
                  style={{
                    fontSize: 9.5,
                    fontFamily: 'Consolas, monospace',
                    fontWeight: 800,
                    color: '#10B981',
                    letterSpacing: '0.5px',
                  }}
                >
                  ONLINE
                </span>
              </div>
            </div>

            {/* Engine Name (Keep in English as requested) */}
            <div>
              <div
                style={{
                  fontSize: isVertical ? 21 : 23,
                  fontWeight: 900,
                  color: '#FFFFFF',
                  letterSpacing: '-0.3px',
                  marginBottom: 4,
                }}
              >
                {engine.name}
              </div>
              <div
                style={{
                  fontSize: isVertical ? (isKhmer ? 12 : 12.5) : 13,
                  color: '#94A3B8',
                  lineHeight: 1.4,
                }}
              >
                {isKhmer ? engine.roleKhmer : engine.role}
              </div>
            </div>

            {/* Bottom Tech HUD Index */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginTop: 14,
                paddingTop: 10,
                borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                fontSize: 10,
                color: engine.color,
                fontWeight: 700,
              }}
            >
              <span>{isKhmer ? `ម៉ាស៊ីនស្កេន #0${idx + 1}` : `ENGINE #0${idx + 1}`}</span>
              <span>{isKhmer ? 'ស្តង់ដារ ZERO-TRUST' : 'ZERO-TRUST AUDIT'}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};