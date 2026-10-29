import React from 'react';
import { AbsoluteFill, Audio, Sequence, staticFile } from 'remotion';
import { SCENES } from '../data/storyboard';
import { Scene1Hook } from '../scenes/Scene1Hook';
import { Scene2Reveal } from '../scenes/Scene2Reveal';
import { Scene3Demo } from '../scenes/Scene3Demo';
import { Scene4Engines } from '../scenes/Scene4Engines';
import { Scene5CTA } from '../scenes/Scene5CTA';
import { SceneTransition } from '../components/SceneTransition';

interface CyberGuardVerticalProps {
  useRealFootage?: boolean;
  language?: 'kh' | 'en';
}

export const CyberGuardVertical: React.FC<CyberGuardVerticalProps> = ({
  useRealFootage = false,
  language = 'kh',
}) => {
  return (
    <AbsoluteFill style={{ backgroundColor: '#0A0E17' }}>
      {/* Scene 1: The Hook (0 - 4s / frames 0 - 120) */}
      <Sequence from={SCENES.HOOK.fromFrame} durationInFrames={SCENES.HOOK.durationInFrames}>
        <Audio src={staticFile('audio/vo_scene1.mp3')} volume={1} />
        <Scene1Hook isVertical={true} language={language} />
      </Sequence>

      {/* Transition 1 -> 2 */}
      <Sequence from={112} durationInFrames={16}>
        <SceneTransition durationInFrames={16} />
      </Sequence>

      {/* Scene 2: Product Reveal (4 - 8s / frames 120 - 240) */}
      <Sequence from={SCENES.REVEAL.fromFrame} durationInFrames={SCENES.REVEAL.durationInFrames}>
        <Audio src={staticFile('audio/vo_scene2.mp3')} volume={1} />
        <Scene2Reveal isVertical={true} language={language} />
      </Sequence>

      {/* Transition 2 -> 3 */}
      <Sequence from={232} durationInFrames={16}>
        <SceneTransition durationInFrames={16} />
      </Sequence>

      {/* Scene 3: Telegram Product Demo (8 - 17s / frames 240 - 510) */}
      <Sequence from={SCENES.DEMO.fromFrame} durationInFrames={SCENES.DEMO.durationInFrames}>
        <Audio src={staticFile('audio/vo_scene3.mp3')} volume={1} />
        <Scene3Demo isVertical={true} useRealFootage={useRealFootage} language={language} />
      </Sequence>

      {/* Transition 3 -> 4 */}
      <Sequence from={502} durationInFrames={16}>
        <SceneTransition durationInFrames={16} />
      </Sequence>

      {/* Scene 4: Engine Showcase (17 - 23s / frames 510 - 690) */}
      <Sequence from={SCENES.ENGINES.fromFrame} durationInFrames={SCENES.ENGINES.durationInFrames}>
        <Audio src={staticFile('audio/vo_scene4.mp3')} volume={1} />
        <Scene4Engines isVertical={true} language={language} />
      </Sequence>

      {/* Transition 4 -> 5 */}
      <Sequence from={682} durationInFrames={16}>
        <SceneTransition durationInFrames={16} />
      </Sequence>

      {/* Scene 5: Call to Action (23 - 30s / frames 690 - 900) */}
      <Sequence from={SCENES.CTA.fromFrame} durationInFrames={SCENES.CTA.durationInFrames}>
        <Audio src={staticFile('audio/vo_scene5.mp3')} volume={1} />
        <Scene5CTA isVertical={true} language={language} />
      </Sequence>
    </AbsoluteFill>
  );
};