import React from 'react';
import { Composition } from 'remotion';
import { CyberGuardVertical } from './compositions/CyberGuardVertical';
import { CyberGuardLandscape } from './compositions/CyberGuardLandscape';
import './index.css';

export const RemotionRoot: React.FC = () => {
  return (
    <>
      {/* Primary Target: TikTok / Reels / Shorts (9:16 Vertical with Khmer Typography & Audio) */}
      <Composition
        id="CyberGuardVerticalKhmer"
        component={CyberGuardVertical}
        durationInFrames={900}
        fps={30}
        width={1080}
        height={1920}
        defaultProps={{
          useRealFootage: false,
          language: 'kh' as const,
        }}
      />

      {/* Standard Vertical Composition */}
      <Composition
        id="CyberGuardVertical"
        component={CyberGuardVertical}
        durationInFrames={900}
        fps={30}
        width={1080}
        height={1920}
        defaultProps={{
          useRealFootage: false,
          language: 'kh' as const,
        }}
      />

      {/* Landscape Composition (16:9 Landscape) */}
      <Composition
        id="CyberGuardLandscape"
        component={CyberGuardLandscape}
        durationInFrames={900}
        fps={30}
        width={1920}
        height={1080}
        defaultProps={{
          useRealFootage: false,
          language: 'kh' as const,
        }}
      />
    </>
  );
};