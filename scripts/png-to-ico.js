/**
 * Convert a PNG to a multi-size ICO file.
 * Uses sips to resize, then packs raw RGBA bitmaps into ICO format.
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync } = require('child_process');

const ASSETS = path.join(__dirname, '..', 'assets');
const srcPng = path.join(ASSETS, 'icon.png');
const outIco = path.join(ASSETS, 'icon.ico');

// ICO sizes to include
const sizes = [16, 24, 32, 48, 64, 128, 256];

// We'll embed PNG data directly in the ICO (PNG-in-ICO format, supported since Vista)
const pngBuffers = [];

for (const size of sizes) {
  const tmpFile = path.join(ASSETS, `_tmp_${size}.png`);
  execSync(`sips -z ${size} ${size} "${srcPng}" --out "${tmpFile}" 2>/dev/null`);
  pngBuffers.push(fs.readFileSync(tmpFile));
  fs.unlinkSync(tmpFile);
}

// Build ICO file
// ICO header: 6 bytes
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0);     // reserved
header.writeUInt16LE(1, 2);     // type: 1 = ICO
header.writeUInt16LE(sizes.length, 4); // image count

// Directory entries: 16 bytes each
const dirSize = sizes.length * 16;
let dataOffset = 6 + dirSize;
const dirEntries = [];
const imageDataBuffers = [];

for (let i = 0; i < sizes.length; i++) {
  const size = sizes[i];
  const pngData = pngBuffers[i];

  const entry = Buffer.alloc(16);
  entry[0] = size < 256 ? size : 0;   // width (0 = 256)
  entry[1] = size < 256 ? size : 0;   // height (0 = 256)
  entry[2] = 0;   // color palette
  entry[3] = 0;   // reserved
  entry.writeUInt16LE(1, 4);          // color planes
  entry.writeUInt16LE(32, 6);         // bits per pixel
  entry.writeUInt32LE(pngData.length, 8);  // data size
  entry.writeUInt32LE(dataOffset, 12);     // data offset

  dirEntries.push(entry);
  imageDataBuffers.push(pngData);
  dataOffset += pngData.length;
}

const ico = Buffer.concat([header, ...dirEntries, ...imageDataBuffers]);
fs.writeFileSync(outIco, ico);
console.log(`Created assets/icon.ico (${sizes.join(', ')}px)`);
