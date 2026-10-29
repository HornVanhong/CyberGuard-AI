const fs = require('fs');
const path = require('path');

const audioDir = path.join(__dirname, 'public', 'audio');
if (!fs.existsSync(audioDir)) {
  fs.mkdirSync(audioDir, { recursive: true });
}

// Valid silent MP3 frame (MPEG 1 Layer III, 128kbps, 44100Hz)
// 0xFF, 0xFB, 0x90, 0x64 followed by 413 bytes of silence (0x00)
const frameSize = 417;
const singleFrame = Buffer.alloc(frameSize, 0);
singleFrame[0] = 0xFF;
singleFrame[1] = 0xFB;
singleFrame[2] = 0x90;
singleFrame[3] = 0x64;

// 30 seconds ~ 1150 frames
const numFrames = 1150;
const fullBuffer = Buffer.alloc(frameSize * numFrames);
for (let i = 0; i < numFrames; i++) {
  singleFrame.copy(fullBuffer, i * frameSize);
}

const outputPath = path.join(audioDir, 'voiceover-khmer.mp3');
fs.writeFileSync(outputPath, fullBuffer);
console.log('Successfully created placeholder voiceover-khmer.mp3, size:', fullBuffer.length);
