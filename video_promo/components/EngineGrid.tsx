import React from 'react';
import { spring, useCurrentFrame, useVideoConfig } from 'remotion';

export interface EngineDef {
  name: string;
  category: string;
  icon: string;
  color: string;
  highlight?: string;
}

export const EngineGrid: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const engines: EngineDef[] = [
    { name: 'ClamAV Antivirus Daemon', category: 'Streaming TCP zINSTREAM', icon: '🛡️', color: '#10b981', highlight: 'HIGH-SPEED' },
    { name: 'YARA Rule Matching', category: 'Webshells & Ransomware Signatures', icon: '⚡', color: '#00f0ff', highlight: 'ACTIVE' },
    { name: 'Ghidra Headless SRE', category: 'NSA Disassembler & Decompiler', icon: '🔬', color: '#38bdf8', highlight: 'DEEP SRE' },
    { name: 'Detect It Easy (DIE)', category: 'PE Packers (UPX, Themida, VMProtect)', icon: '📦', color: '#10b981', highlight: 'PACKERS' },
    { name: 'oletools (olevba)', category: 'VBA Macros & AutoOpen Triggers', icon: '📑', color: '#f59e0b', highlight: 'OFFICE' },
    { name: 'capa PE Capability Analyzer', category: 'Dangerous Win32 APIs & Injections', icon: '🔍', color: '#10b981', highlight: 'BEHAVIOR' },
    { name: 'ExifTool & PDFiD', category: 'Metadata, Polyglots & JavaScript Streams', icon: '📄', color: '#00f0ff', highlight: 'STRUCTURAL' },
    { name: 'Google Gemini AI Engine', category: 'Structured Security Verdict in EN/KH', icon: '✨', color: '#8b5cf6', highlight: 'LLM REASONING' },
    { name: 'Gitleaks Secret Scanner', category: 'Redacts AWS, GitHub & Private Keys', icon: '🔑', color: '#ef4444', highlight: 'CREDENTIALS' },
    { name: 'Magic Byte Validator', category: 'Detects Disguised Extensions (MZ/PK)', icon: '🧬', color: '#10b981', highlight: 'VALIDATION' },
    { name: 'Decompression Bomb Guard', category: 'Zip Bomb 100:1 Ratio & Traversal Defense', icon: '💣', color: '#f59e0b', highlight: 'ARCHIVE' },
    { name: 'Cloudflare Edge Gateway', category: 'Serverless Telegram Webhook Sandbox', icon: '🌐', color: '#00f0ff', highlight: 'EDGE 0ms' },
  ];

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 16,
        width: '100%',
        maxWidth: 1440,
        margin: '0 auto',
      }}
    >
      {engines.map((engine, idx) => {
        // Staggered spring entrance using damping: 12
        const cardSpring = spring({
          fps,
          frame: frame - (idx * 4),
          config: { damping: 12, mass: 0.5, stiffness: 100 },
        });

        const isVisible = frame >= idx * 4;

        return (
          <div
            key={idx}
            style={{
              transform: `scale(${cardSpring})`,
              opacity: isVisible ? Math.min(1, cardSpring) : 0,
              backgroundColor: 'rgba(17, 24, 39, 0.85)',
              border: `1px solid ${engine.color}44`,
              borderRadius: 14,
              padding: '16px 18px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              boxShadow: `0 8px 24px rgba(0,0,0,0.5), inset 0 0 16px ${engine.color}11`,
              backdropFilter: 'blur(14px)',
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            {/* Top status bar */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 20 }}>{engine.icon}</span>
                <span
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: '50%',
                    backgroundColor: engine.color,
                    boxShadow: `0 0 8px ${engine.color}`,
                    display: 'inline-block',
                  }}
                />
              </div>
              <span
                style={{
                  fontSize: 10,
                  fontFamily: 'Consolas, monospace',
                  fontWeight: 800,
                  color: engine.color,
                  backgroundColor: `${engine.color}18`,
                  padding: '2px 8px',
                  borderRadius: 4,
                  letterSpacing: '1px',
                }}
              >
                {engine.highlight}
              </span>
            </div>

            {/* Title & Category */}
            <div>
              <div
                style={{
                  fontSize: 15,
                  fontWeight: 800,
                  color: '#ffffff',
                  fontFamily: '"Montserrat", "Inter", sans-serif',
                  letterSpacing: '0.3px',
                }}
              >
                {engine.name}
              </div>
              <div
                style={{
                  fontSize: 11,
                  color: '#9ca3af',
                  marginTop: 4,
                  lineHeight: 1.4,
                }}
              >
                {engine.category}
              </div>
            </div>

            {/* Bottom active inspection indicator */}
            <div
              style={{
                marginTop: 10,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                borderTop: '1px solid rgba(255,255,255,0.06)',
                paddingTop: 8,
                fontSize: 10,
                color: '#6b7280',
                fontFamily: 'Consolas, monospace',
              }}
            >
              <span>ENGINE #0{idx + 1}</span>
              <span style={{ color: engine.color }}>● ONLINE</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
