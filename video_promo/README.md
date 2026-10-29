# 🛡️ CyberGuard AI — Promotional Video (Remotion)

This directory contains the production-ready Remotion motion graphics source code for the 30-second promotional tech video announcing **CyberGuard AI — Telegram Malware Scanner & Security Assistant**.

## 🎬 Video Specifications
- **Compositions:**
  - `CyberGuardPromo`: `1920x1080` (16:9 Landscape for YouTube, Twitter, Web)
  - `CyberGuardPromoVertical`: `1080x1920` (9:16 Vertical for TikTok, Instagram Reels, Shorts)
- **Duration:** 30 seconds (900 frames at 30 FPS)
- **Theme:** Dark Cyber Defense (Deep Navy `#0a0e17`, Neon Cyan `#00f0ff`, Emerald Green `#10b981`, Alert Crimson `#ef4444`)
- **Physics:** Spring animations with `damping: 15, mass: 0.5, stiffness: 100`

## ⏱️ Storyboard & Scene Breakdown
1. **Scene 1: The Hook (0s - 5s / Frames 0 - 150)**
   - Dynamic dark cyber grid, pulsating particles, critical warning badge.
   - Text wipe and glitch: *"Every day, thousands of suspicious files enter your chat."*
2. **Scene 2: Introducing CyberGuard AI (5s - 11s / Frames 150 - 330)**
   - Holographic Cyber Shield logo burst with neon rings.
   - *"Meet CyberGuard AI — Your 24/7 Telegram Cybersecurity Assistant"*
   - Subtitle: *"Cloudflare Edge Gateway • Google Gemini AI • Deep Malware Analysis"*
3. **Scene 3: The 12 Heavy-Duty Inspection Engines (11s - 18s / Frames 330 - 540)**
   - High-tech HUD grid showcasing all 12 engines: ClamAV, YARA, Ghidra SRE, Detect It Easy, oletools, capa, ExifTool, PDFiD, Gemini AI, Gitleaks, Magic Byte Validator, and Decompression Bomb Guard.
4. **Scene 4: Interactive Telegram Experience (18s - 24s / Frames 540 - 720)**
   - Realistic animated Telegram chat mockup.
   - Drop file `suspicious_payload.exe` → Scanning progress → Full Report Card (`🔴 MALICIOUS 95/100`).
   - Google Gemini AI technical explanation in English and Khmer (`ភាសាខ្មែរ`).
   - Interactive Telegram inline keyboard (`🔬 Ghidra Decompile`, `📑 Forensic Report`, `🤖 Ask AI`, `🌐 VirusTotal`).
5. **Scene 5: Call to Action (24s - 30s / Frames 720 - 900)**
   - 3D-styled Telegram send button + Cyber QR code.
   - Bot username: `@CyberGuardMalwareBot`
   - Tagline: *"Always Free • Zero-Trust • 24/7 Serverless Edge"*

## 🚀 How to Preview & Render
From the Remotion project workspace (`d:\Video\my-video`):

```bash
# 1. Preview interactively in Remotion Studio
npm run dev

# 2. Render 16:9 Landscape MP4 (1920x1080)
npx remotion render CyberGuardPromo out/CyberGuardPromo.mp4

# 3. Render 9:16 Vertical MP4 (1080x1920)
npx remotion render CyberGuardPromoVertical out/CyberGuardPromoVertical.mp4
```
