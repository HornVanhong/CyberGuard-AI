import React from 'react';
import { AbsoluteFill, Sequence } from 'remotion';
import { Scene1Hook } from './scenes/Scene1Hook';
import { Scene2Intro } from './scenes/Scene2Intro';
import { Scene3Engines } from './scenes/Scene3Engines';
import { Scene4TelegramChat } from './scenes/Scene4TelegramChat';
import { Scene5CallToAction } from './scenes/Scene5CallToAction';

export const CyberGuardVideo: React.FC = () => {
  return (
    <AbsoluteFill style={{ backgroundColor: '#0a0e17' }}>
      {/* SCENE 1 — THE HOOK (0s - 5s / Frames 0 - 150) */}
      <Sequence from={0} durationInFrames={150} name="1. The Hook">
        <Scene1Hook />
      </Sequence>

      {/* SCENE 2 — INTRODUCING CYBERGUARD AI (5s - 11s / Frames 150 - 330) */}
      <Sequence from={150} durationInFrames={180} name="2. Introduce CyberGuard AI">
        <Scene2Intro />
      </Sequence>

      {/* SCENE 3 — 12 INSPECTION ENGINES (11s - 18s / Frames 330 - 540) */}
      <Sequence from={330} durationInFrames={210} name="3. 12 Inspection Engines">
        <Scene3Engines />
      </Sequence>

      {/* SCENE 4 — INTERACTIVE TELEGRAM EXPERIENCE (18s - 24s / Frames 540 - 720) */}
      <Sequence from={540} durationInFrames={180} name="4. Telegram Chat Experience">
        <Scene4TelegramChat />
      </Sequence>

      {/* SCENE 5 — CALL TO ACTION (24s - 30s / Frames 720 - 900) */}
      <Sequence from={720} durationInFrames={180} name="5. Call To Action">
        <Scene5CallToAction />
      </Sequence>
    </AbsoluteFill>
  );
};
