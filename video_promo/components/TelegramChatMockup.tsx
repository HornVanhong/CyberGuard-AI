import React from 'react';
import { interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';

export const TelegramChatMockup: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // 1. User file upload entrance (frame 10+)
  const userUploadSpring = spring({
    frame: frame - 10,
    fps,
    config: { damping: 14, stiffness: 85 },
  });

  // 2. Bot analyzing status (frame 35+)
  const analyzingSpring = spring({
    frame: frame - 35,
    fps,
    config: { damping: 14, stiffness: 85 },
  });

  // 3. Security Report Card (frame 70+)
  const reportSpring = spring({
    frame: frame - 70,
    fps,
    config: { damping: 14, stiffness: 80 },
  });

  // 4. Gemini AI Explanation (frame 110+)
  const geminiSpring = spring({
    frame: frame - 110,
    fps,
    config: { damping: 14, stiffness: 85 },
  });

  // 5. Inline Action Keyboard (frame 135+)
  const keyboardSpring = spring({
    frame: frame - 135,
    fps,
    config: { damping: 14, stiffness: 90 },
  });

  return (
    <div
      style={{
        width: 860,
        backgroundColor: '#0e1621',
        borderRadius: 20,
        border: '1px solid rgba(0, 240, 255, 0.25)',
        boxShadow: '0 25px 60px rgba(0, 0, 0, 0.7), 0 0 35px rgba(0, 240, 255, 0.15)',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Telegram Chat Header */}
      <div
        style={{
          height: 60,
          backgroundColor: '#17212b',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          {/* Bot Avatar */}
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #00f0ff 0%, #0051ff 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 20,
              boxShadow: '0 0 12px rgba(0, 240, 255, 0.5)',
            }}
          >
            🛡️
          </div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#ffffff' }}>
              CyberGuard AI <span style={{ fontSize: 12, color: '#00f0ff' }}>✔</span>
            </div>
            <div style={{ fontSize: 11, color: '#10b981' }}>bot • 24/7 Security Engine Online</div>
          </div>
        </div>

        <div style={{ fontSize: 12, color: '#64748b', fontFamily: 'Consolas, monospace' }}>
          @CyberGuardMalwareBot
        </div>
      </div>

      {/* Telegram Chat Message Stream */}
      <div
        style={{
          padding: '24px 28px',
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
          backgroundColor: '#0a0f1d',
          minHeight: 460,
        }}
      >
        {/* 1. User Message (File Drop: payload.exe) */}
        {frame >= 10 && (
          <div
            style={{
              alignSelf: 'flex-end',
              transform: `scale(${userUploadSpring})`,
              opacity: interpolate(frame, [10, 25], [0, 1], { extrapolateRight: 'clamp' }),
              backgroundColor: '#2b5278',
              borderRadius: '16px 16px 4px 16px',
              padding: '12px 18px',
              maxWidth: 420,
              boxShadow: '0 4px 15px rgba(0,0,0,0.3)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: 10,
                  backgroundColor: 'rgba(239, 68, 68, 0.2)',
                  border: '1px solid #ef4444',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 22,
                }}
              >
                ⚠️
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#ffffff' }}>
                  suspicious_payload.exe
                </div>
                <div style={{ fontSize: 11, color: '#93c5fd', marginTop: 2 }}>
                  1.42 MB • PE32+ Executable
                </div>
              </div>
            </div>
            <div style={{ textAlign: 'right', fontSize: 10, color: '#93c5fd', marginTop: 6 }}>
              11:42 AM ✔✔
            </div>
          </div>
        )}

        {/* 2. Bot Status: Analyzing with ClamAV & YARA */}
        {frame >= 35 && frame < 70 && (
          <div
            style={{
              alignSelf: 'flex-start',
              transform: `scale(${analyzingSpring})`,
              backgroundColor: '#182533',
              borderRadius: '16px 16px 16px 4px',
              padding: '12px 20px',
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              border: '1px solid rgba(0, 240, 255, 0.2)',
            }}
          >
            <div style={{ fontSize: 16 }}>🔄</div>
            <div style={{ fontSize: 13, color: '#00f0ff', fontFamily: 'Consolas, monospace' }}>
              Scanning with ClamAV TCP, YARA rules & Ghidra...
            </div>
          </div>
        )}

        {/* 3. Bot Full Security Report Card (frame 70+) */}
        {frame >= 70 && (
          <div
            style={{
              alignSelf: 'flex-start',
              transform: `scale(${reportSpring})`,
              backgroundColor: '#182533',
              border: '1px solid rgba(239, 68, 68, 0.45)',
              borderRadius: '18px 18px 18px 4px',
              padding: '16px 20px',
              maxWidth: 580,
              boxShadow: '0 8px 30px rgba(239, 68, 68, 0.15)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 800, color: '#ef4444', letterSpacing: '1px' }}>
                🛡️ CYBERGUARD AI REPORT
              </div>
              <div style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 800 }}>
                🔴 MALICIOUS (95/100)
              </div>
            </div>

            <div style={{ fontSize: 12, color: '#cbd5e1', lineHeight: '20px', fontFamily: 'Consolas, monospace' }}>
              <div>📁 <b>File:</b> suspicious_payload.exe (1.42 MB)</div>
              <div>🧬 <b>Detected Type:</b> Windows PE32+ (UPX Packed)</div>
              <div>🚨 <b>ClamAV:</b> <span style={{ color: '#ef4444' }}>Win.Trojan.Agent-9821</span></div>
              <div>⚠️ <b>YARA:</b> <span style={{ color: '#ef4444' }}>CobaltStrike_Beacon, Obfuscated_Shell</span></div>
              <div>🔍 <b>capa API:</b> VirtualAllocEx, CreateRemoteThread</div>
            </div>
          </div>
        )}

        {/* 4. Gemini AI Explanation (frame 110+) */}
        {frame >= 110 && (
          <div
            style={{
              alignSelf: 'flex-start',
              transform: `scale(${geminiSpring})`,
              backgroundColor: 'rgba(139, 92, 246, 0.12)',
              border: '1px solid rgba(139, 92, 246, 0.4)',
              borderRadius: '14px',
              padding: '12px 18px',
              maxWidth: 580,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 14 }}>✨</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#c4b5fd' }}>
                GOOGLE GEMINI AI INSIGHT
              </span>
            </div>
            <div style={{ fontSize: 12, color: '#f3f4f6', lineHeight: 1.5 }}>
              Critical Threat: This binary drops an encrypted payload and attempts process injection.
            </div>
            <div style={{ fontSize: 12, color: '#a78bfa', marginTop: 4, fontFamily: '"Kantumruy Pro", sans-serif' }}>
              គ្រោះថ្នាក់កម្រិតខ្ពស់! កម្មវិធីនេះព្យាយាមចាក់បញ្ចូលកូដគ្រោះថ្នាក់ (Process Injection)។
            </div>
          </div>
        )}

        {/* 5. Interactive Telegram Inline Action Keyboard (frame 135+) */}
        {frame >= 135 && (
          <div
            style={{
              alignSelf: 'flex-start',
              transform: `scale(${keyboardSpring})`,
              display: 'grid',
              gridTemplateColumns: 'repeat(2, 1fr)',
              gap: 8,
              width: 580,
            }}
          >
            <div style={{ backgroundColor: '#2b5278', padding: '8px 14px', borderRadius: 8, textAlign: 'center', fontSize: 12, color: '#ffffff', fontWeight: 600, border: '1px solid rgba(255,255,255,0.1)' }}>
              🔬 Ghidra Decompile
            </div>
            <div style={{ backgroundColor: '#2b5278', padding: '8px 14px', borderRadius: 8, textAlign: 'center', fontSize: 12, color: '#ffffff', fontWeight: 600, border: '1px solid rgba(255,255,255,0.1)' }}>
              📑 Download Forensic Report
            </div>
            <div style={{ backgroundColor: '#2b5278', padding: '8px 14px', borderRadius: 8, textAlign: 'center', fontSize: 12, color: '#ffffff', fontWeight: 600, border: '1px solid rgba(255,255,255,0.1)' }}>
              🤖 Ask AI Assistant (/ask)
            </div>
            <div style={{ backgroundColor: '#2b5278', padding: '8px 14px', borderRadius: 8, textAlign: 'center', fontSize: 12, color: '#ffffff', fontWeight: 600, border: '1px solid rgba(255,255,255,0.1)' }}>
              🌐 VirusTotal (48/72 Engines)
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
