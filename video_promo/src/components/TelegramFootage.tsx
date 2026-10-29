import React from 'react';
import { interpolate, spring, staticFile, useCurrentFrame, useVideoConfig, OffthreadVideo, Img } from 'remotion';

interface TelegramFootageProps {
  useRealFootage?: boolean;
  language?: 'kh' | 'en';
}

export const TelegramFootage: React.FC<TelegramFootageProps> = ({
  useRealFootage = false,
  language = 'kh',
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const isKhmer = language === 'kh';

  // Entrance spring for phone container
  const phoneEntrance = spring({
    fps,
    frame,
    config: { damping: 14, mass: 0.6, stiffness: 90 },
  });

  // Dynamic cinematic camera pan & zoom across the 270 frames of Scene 3
  const cameraScale = interpolate(
    frame,
    [0, 50, 100, 180, 240, 270],
    [0.92, 1.0, 1.15, 1.25, 1.05, 1.0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }
  );

  const cameraTranslateY = interpolate(
    frame,
    [0, 60, 120, 190, 250, 270],
    [30, 0, -60, -180, -20, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }
  );

  // Progressive message reveal timing
  const showUserMessage = frame >= 25;
  const showScanningState = frame >= 65 && frame < 110;
  const showBotVerdict = frame >= 110;
  const showGeminiExplanation = frame >= 150;
  const showActionButtons = frame >= 195;

  // Scanline pulse
  const laserY = (frame * 6) % 650;

  return (
    <div
      style={{
        position: 'relative',
        width: 520,
        height: 1040,
        margin: '0 auto',
        transform: `scale(${phoneEntrance * cameraScale}) translateY(${cameraTranslateY}px)`,
        transformOrigin: 'center center',
      }}
    >
      {/* Smartphone Outer Chassis (iPhone 16 Pro Style) */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          borderRadius: 54,
          padding: 12,
          background: 'linear-gradient(145deg, #2A364F, #0E1522, #1C273C)',
          boxShadow: `
            0 25px 60px rgba(0, 0, 0, 0.85),
            0 0 35px rgba(0, 240, 255, 0.22),
            inset 0 0 4px rgba(255, 255, 255, 0.25)
          `,
          display: 'flex',
          flexDirection: 'column',
          border: '1.5px solid rgba(0, 240, 255, 0.35)',
        }}
      >
        {/* Smartphone Screen Inner */}
        <div
          style={{
            position: 'relative',
            flex: 1,
            borderRadius: 44,
            backgroundColor: '#0F172A',
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column',
            border: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          {/* Dynamic Island / Pill Camera */}
          <div
            style={{
              position: 'absolute',
              top: 10,
              left: '50%',
              transform: 'translateX(-50%)',
              width: 124,
              height: 28,
              borderRadius: 20,
              backgroundColor: '#000000',
              zIndex: 50,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0 12px',
              border: '1px solid rgba(255, 255, 255, 0.08)',
            }}
          >
            <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: '#0A0F1D', border: '1.5px solid #1E293B' }} />
            <div style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: '#10B981', boxShadow: '0 0 6px #10B981' }} />
          </div>

          {/* Real Footage Mode */}
          {useRealFootage ? (
            <div style={{ position: 'relative', width: '100%', height: '100%' }}>
              <OffthreadVideo
                src={staticFile('media/telegram-demo.mp4')}
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
              />
            </div>
          ) : (
            /* High-Fidelity Telegram CyberGuard Bot UI */
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                height: '100%',
                backgroundColor: '#0B111E',
                color: '#F4F7FB',
                fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
              }}
            >
              {/* Telegram Header Bar */}
              <div
                style={{
                  paddingTop: 46,
                  paddingBottom: 12,
                  paddingLeft: 18,
                  paddingRight: 18,
                  backgroundColor: 'rgba(15, 23, 42, 0.95)',
                  borderBottom: '1px solid rgba(0, 240, 255, 0.18)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  zIndex: 20,
                }}
              >
                {/* Back Arrow */}
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#00F0FF" strokeWidth="2.5">
                  <path d="M19 12H5M12 19l-7-7 7-7" strokeLinecap="round" strokeLinejoin="round" />
                </svg>

                {/* Bot Avatar */}
                <div
                  style={{
                    position: 'relative',
                    width: 40,
                    height: 40,
                    borderRadius: '50%',
                    backgroundColor: '#0A0E17',
                    border: '1.5px solid #00F0FF',
                    boxShadow: '0 0 14px rgba(0, 240, 255, 0.5)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Img
                    src={staticFile('logo.jpg')}
                    alt="CyberGuard AI Bot"
                    style={{
                      width: '100%',
                      height: '100%',
                      borderRadius: '50%',
                      objectFit: 'cover',
                    }}
                  />
                  <div
                    style={{
                      position: 'absolute',
                      bottom: -1,
                      right: -1,
                      width: 11,
                      height: 11,
                      borderRadius: '50%',
                      backgroundColor: '#10B981',
                      border: '2px solid #0F172A',
                    }}
                  />
                </div>

                {/* Title & Status */}
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontWeight: 800, fontSize: 15, letterSpacing: '-0.3px', color: '#FFFFFF' }}>
                      CyberGuard AI
                    </span>
                    <span
                      style={{
                        backgroundColor: 'rgba(0, 240, 255, 0.16)',
                        color: '#00F0FF',
                        fontSize: 9.5,
                        fontWeight: 800,
                        padding: '2px 6px',
                        borderRadius: 6,
                        border: '1px solid rgba(0, 240, 255, 0.3)',
                      }}
                    >
                      BOT
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: '#10B981', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: '#10B981' }} />
                    {isKhmer ? 'ប្រព័ន្ធដំណើរការ ២៤/៧' : '24/7 Serverless Edge Active'}
                  </div>
                </div>

                {/* Menu dots */}
                <div style={{ color: '#64748B', fontSize: 20 }}>⋮</div>
              </div>

              {/* Replaceable Footage Badge Overlay */}
              <div
                style={{
                  backgroundColor: 'rgba(0, 240, 255, 0.12)',
                  borderBottom: '1px solid rgba(0, 240, 255, 0.25)',
                  padding: '5px 12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6,
                  fontSize: 10,
                  fontFamily: 'Consolas, monospace',
                  color: '#00F0FF',
                  letterSpacing: '0.5px',
                }}
              >
                <span style={{ animation: 'blink 1s infinite' }}>●</span>
                <span>REPLACEABLE SLOT: public/media/telegram-demo.mp4</span>
              </div>

              {/* Telegram Chat Message Stream */}
              <div
                style={{
                  flex: 1,
                  padding: '16px 14px',
                  overflow: 'hidden',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 14,
                  position: 'relative',
                }}
              >
                {/* Security Shield Watermark */}
                <div
                  style={{
                    position: 'absolute',
                    top: '40%',
                    left: '50%',
                    transform: 'translate(-50%, -50%)',
                    opacity: 0.04,
                    fontSize: 220,
                    pointerEvents: 'none',
                  }}
                >
                  🛡️
                </div>

                {/* Date separator */}
                <div style={{ textAlign: 'center' }}>
                  <span
                    style={{
                      backgroundColor: 'rgba(30, 41, 59, 0.85)',
                      padding: '3px 12px',
                      borderRadius: 12,
                      fontSize: 10,
                      color: '#94A3B8',
                      fontFamily: 'Consolas, monospace',
                    }}
                  >
                    TODAY
                  </span>
                </div>

                {/* Message 1: User Drops Suspicious File */}
                {showUserMessage && (
                  <div
                    style={{
                      alignSelf: 'flex-end',
                      maxWidth: '82%',
                      backgroundColor: '#1E3A5F',
                      borderRadius: '16px 16px 4px 16px',
                      padding: '10px 12px',
                      border: '1px solid rgba(0, 240, 255, 0.3)',
                      boxShadow: '0 4px 12px rgba(0, 0, 0, 0.4)',
                    }}
                  >
                    {/* Attachment preview */}
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        backgroundColor: 'rgba(15, 23, 42, 0.6)',
                        padding: '8px 10px',
                        borderRadius: 10,
                        border: '1px solid rgba(239, 68, 68, 0.4)',
                      }}
                    >
                      <div
                        style={{
                          width: 36,
                          height: 36,
                          borderRadius: 8,
                          backgroundColor: 'rgba(239, 68, 68, 0.2)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: 18,
                        }}
                      >
                        ⚠️
                      </div>
                      <div style={{ overflow: 'hidden' }}>
                        <div style={{ fontSize: 12.5, fontWeight: 700, color: '#F4F7FB' }}>
                          Invoice_March2025.pdf.exe
                        </div>
                        <div style={{ fontSize: 10, color: '#EF4444', fontFamily: 'Consolas, monospace' }}>
                          2.4 MB • Double Extension!
                        </div>
                      </div>
                    </div>
                    <div style={{ fontSize: isKhmer ? 11.5 : 12, marginTop: 6, color: '#E2E8F0', lineHeight: 1.4 }}>
                      {isKhmer
                        ? 'ជួយពិនិត្យមើលឯកសារវិក្កយបត្រនេះបន្តិច តើមានសុវត្ថិភាពទេ?'
                        : 'Can you check if this invoice is safe to open?'}
                    </div>
                    <div style={{ textAlign: 'right', fontSize: 9.5, color: '#94A3B8', marginTop: 2 }}>
                      12:42 PM ✓✓
                    </div>
                  </div>
                )}

                {/* Progress / Scanning State */}
                {showScanningState && (
                  <div
                    style={{
                      alignSelf: 'flex-start',
                      backgroundColor: 'rgba(15, 23, 42, 0.85)',
                      borderRadius: '14px',
                      padding: '8px 14px',
                      border: '1px solid rgba(0, 240, 255, 0.4)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      fontSize: 11,
                      color: '#00F0FF',
                      fontFamily: 'Consolas, monospace',
                    }}
                  >
                    <div
                      style={{
                        width: 20,
                        height: 20,
                        borderRadius: '50%',
                        overflow: 'hidden',
                        border: '1px solid #00F0FF',
                        flexShrink: 0,
                      }}
                    >
                      <Img
                        src={staticFile('logo.jpg')}
                        style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                      />
                    </div>
                    {isKhmer
                      ? 'កំពុងវិភាគតាមរយៈ ClamAV, YARA និង Ghidra...'
                      : 'Analyzing via ClamAV, YARA & Ghidra...'}
                  </div>
                )}

                {/* Message 2: Bot Verdict Card */}
                {showBotVerdict && (
                  <div
                    style={{
                      alignSelf: 'flex-start',
                      maxWidth: '92%',
                      backgroundColor: 'rgba(15, 23, 42, 0.95)',
                      borderRadius: '4px 16px 16px 16px',
                      padding: '12px 14px',
                      border: '1.5px solid #EF4444',
                      boxShadow: '0 8px 24px rgba(239, 68, 68, 0.28)',
                    }}
                  >
                    {/* Header Banner */}
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        paddingBottom: 8,
                        borderBottom: '1px solid rgba(239, 68, 68, 0.3)',
                        marginBottom: 8,
                      }}
                    >
                      <div
                        style={{
                          width: 22,
                          height: 22,
                          borderRadius: '50%',
                          backgroundColor: '#EF4444',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: 12,
                          color: '#FFFFFF',
                          fontWeight: 900,
                        }}
                      >
                        ✕
                      </div>
                      <div>
                        <div style={{ fontSize: isKhmer ? 12 : 13, fontWeight: 900, color: '#EF4444', letterSpacing: '0.3px' }}>
                          {isKhmer ? '🔴 រកឃើញមេរោគគ្រោះថ្នាក់ខ្ពស់' : '🔴 MALICIOUS THREAT DETECTED'}
                        </div>
                        <div style={{ fontSize: 9.5, color: '#94A3B8' }}>
                          {isKhmer ? 'កម្រិតភាពត្រឹមត្រូវ ៩៩.៨% • ហានិភ័យខ្ពស់' : 'Verdict Confidence: 99.8% • High Risk'}
                        </div>
                      </div>
                    </div>

                    {/* Threat Engine Matches */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 11 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'Consolas, monospace' }}>
                        <span style={{ color: '#94A3B8' }}>🛡️ ClamAV:</span>
                        <span style={{ color: '#EF4444', fontWeight: 700 }}>Win.Trojan.AgentTesla-9943</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'Consolas, monospace' }}>
                        <span style={{ color: '#94A3B8' }}>⚡ YARA:</span>
                        <span style={{ color: '#F59E0B', fontWeight: 700 }}>SUSP_DISCORD_TOKEN_GRABBER</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'Consolas, monospace' }}>
                        <span style={{ color: '#94A3B8' }}>📦 DIE Packer:</span>
                        <span style={{ color: '#38BDF8', fontWeight: 700 }}>Themida / UPX Obfuscation</span>
                      </div>
                    </div>

                    {/* Gemini AI Breakdown Bubble */}
                    {showGeminiExplanation && (
                      <div
                        style={{
                          marginTop: 10,
                          padding: '8px 10px',
                          borderRadius: 10,
                          backgroundColor: 'rgba(139, 92, 246, 0.12)',
                          border: '1px solid rgba(139, 92, 246, 0.4)',
                        }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 5,
                            fontSize: 10.5,
                            fontWeight: 800,
                            color: '#C084FC',
                            marginBottom: 4,
                          }}
                        >
                          <span>{isKhmer ? '✨ ការវិភាគដោយ Google Gemini AI៖' : '✨ Google Gemini Threat Summary:'}</span>
                        </div>
                        <div style={{ fontSize: isKhmer ? 10 : 10.5, lineHeight: 1.45, color: '#E2E8F0' }}>
                          {isKhmer
                            ? 'ឯកសារនេះជាមេរោគក្លែងបន្លំជា PDF។ នៅពេលបើកដំណើរការ វាព្យាយាមលួចយក Telegram Session និង Password ពី Browser របស់អ្នកបញ្ជូនចេញក្រៅ។'
                            : 'This file disguises an executable as a PDF. Once launched, it initiates a credential stealer targeting Telegram sessions and browser passwords.'}
                        </div>
                      </div>
                    )}

                    {/* Telegram Interactive Action Buttons */}
                    {showActionButtons && (
                      <div
                        style={{
                          display: 'grid',
                          gridTemplateColumns: '1fr 1fr',
                          gap: 6,
                          marginTop: 10,
                        }}
                      >
                        <div
                          style={{
                            backgroundColor: 'rgba(56, 189, 248, 0.15)',
                            border: '1px solid rgba(56, 189, 248, 0.45)',
                            borderRadius: 8,
                            padding: '6px 8px',
                            textAlign: 'center',
                            fontSize: 10,
                            fontWeight: 700,
                            color: '#38BDF8',
                          }}
                        >
                          🔬 Ghidra Decompile
                        </div>
                        <div
                          style={{
                            backgroundColor: 'rgba(16, 185, 129, 0.15)',
                            border: '1px solid rgba(16, 185, 129, 0.45)',
                            borderRadius: 8,
                            padding: '6px 8px',
                            textAlign: 'center',
                            fontSize: 10,
                            fontWeight: 700,
                            color: '#10B981',
                          }}
                        >
                          {isKhmer ? '📑 របាយការណ៍លម្អិត' : '📑 Forensic Report'}
                        </div>
                      </div>
                    )}

                    <div style={{ textAlign: 'right', fontSize: 9.5, color: '#94A3B8', marginTop: 6 }}>
                      12:42 PM
                    </div>
                  </div>
                )}
              </div>

              {/* Chat Input Bar */}
              <div
                style={{
                  padding: '12px 14px',
                  backgroundColor: '#0F172A',
                  borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                }}
              >
                <div style={{ color: '#00F0FF', fontSize: 18 }}>📎</div>
                <div
                  style={{
                    flex: 1,
                    backgroundColor: '#1E293B',
                    borderRadius: 20,
                    padding: '8px 14px',
                    fontSize: 11.5,
                    color: '#64748B',
                  }}
                >
                  {isKhmer ? 'ផ្ញើឯកសារមកដើម្បីស្កេន...' : 'Forward file to scan...'}
                </div>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: '50%',
                    backgroundColor: '#00F0FF',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#0A0E17',
                    fontWeight: 900,
                    fontSize: 14,
                  }}
                >
                  ➤
                </div>
              </div>
            </div>
          )}

          {/* Holographic Laser Sweep */}
          <div
            style={{
              position: 'absolute',
              top: laserY,
              left: 0,
              right: 0,
              height: 2,
              background: 'linear-gradient(90deg, transparent, #00F0FF, transparent)',
              boxShadow: '0 0 12px #00F0FF',
              pointerEvents: 'none',
              opacity: 0.6,
            }}
          />
        </div>
      </div>
    </div>
  );
};