/**
 * Generate a placeholder app icon for the FedRAMP RET Tool.
 * Creates a 1024x1024 PNG using raw pixel buffer (no external deps).
 * Then uses macOS `sips` and `iconutil` to produce .icns and .ico.
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZE = 1024;
const ASSETS = path.join(__dirname, '..', 'assets');

// Simple PNG encoder (RGBA, no filtering)
function createPNG(width, height, pixels) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  function chunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const typeBuffer = Buffer.from(type);
    const crc32 = crc(Buffer.concat([typeBuffer, data]));
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32 >>> 0);
    return Buffer.concat([len, typeBuffer, data, crcBuf]);
  }

  // CRC32
  function crc(buf) {
    let c = 0xFFFFFFFF;
    for (let i = 0; i < buf.length; i++) {
      c ^= buf[i];
      for (let j = 0; j < 8; j++) {
        c = (c >>> 1) ^ (c & 1 ? 0xEDB88320 : 0);
      }
    }
    return c ^ 0xFFFFFFFF;
  }

  // IHDR
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  // IDAT — raw pixel data with filter byte 0 per row
  const rowLen = width * 4 + 1;
  const raw = Buffer.alloc(rowLen * height);
  for (let y = 0; y < height; y++) {
    raw[y * rowLen] = 0; // filter: none
    pixels.copy(raw, y * rowLen + 1, y * width * 4, (y + 1) * width * 4);
  }
  const compressed = zlib.deflateSync(raw, { level: 6 });

  // IEND
  const iend = chunk('IEND', Buffer.alloc(0));

  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', compressed),
    iend,
  ]);
}

// ── Draw the icon ──
const pixels = Buffer.alloc(SIZE * SIZE * 4);

function setPixel(x, y, r, g, b, a = 255) {
  if (x < 0 || x >= SIZE || y < 0 || y >= SIZE) return;
  const i = (y * SIZE + x) * 4;
  // Alpha blend
  const srcA = a / 255;
  const dstA = pixels[i + 3] / 255;
  const outA = srcA + dstA * (1 - srcA);
  if (outA > 0) {
    pixels[i] = Math.round((r * srcA + pixels[i] * dstA * (1 - srcA)) / outA);
    pixels[i + 1] = Math.round((g * srcA + pixels[i + 1] * dstA * (1 - srcA)) / outA);
    pixels[i + 2] = Math.round((b * srcA + pixels[i + 2] * dstA * (1 - srcA)) / outA);
    pixels[i + 3] = Math.round(outA * 255);
  }
}

function fillRect(x0, y0, w, h, r, g, b, a = 255) {
  for (let y = y0; y < y0 + h && y < SIZE; y++) {
    for (let x = x0; x < x0 + w && x < SIZE; x++) {
      setPixel(x, y, r, g, b, a);
    }
  }
}

function fillCircle(cx, cy, radius, r, g, b, a = 255) {
  const r2 = radius * radius;
  for (let y = Math.floor(cy - radius); y <= Math.ceil(cy + radius); y++) {
    for (let x = Math.floor(cx - radius); x <= Math.ceil(cx + radius); x++) {
      const dx = x - cx;
      const dy = y - cy;
      if (dx * dx + dy * dy <= r2) {
        setPixel(x, y, r, g, b, a);
      }
    }
  }
}

function fillRoundedRect(x0, y0, w, h, radius, r, g, b, a = 255) {
  // Fill main body
  fillRect(x0 + radius, y0, w - 2 * radius, h, r, g, b, a);
  fillRect(x0, y0 + radius, w, h - 2 * radius, r, g, b, a);
  // Corners
  fillCircle(x0 + radius, y0 + radius, radius, r, g, b, a);
  fillCircle(x0 + w - radius - 1, y0 + radius, radius, r, g, b, a);
  fillCircle(x0 + radius, y0 + h - radius - 1, radius, r, g, b, a);
  fillCircle(x0 + w - radius - 1, y0 + h - radius - 1, radius, r, g, b, a);
}

// Background — deep navy blue with rounded corners
fillRoundedRect(0, 0, SIZE, SIZE, 180, 15, 30, 75);

// Shield shape — FedRAMP-inspired
const shieldCx = SIZE / 2;
const shieldTop = 180;
const shieldWidth = 420;
const shieldHeight = 560;

// Draw shield body (lighter blue)
for (let y = shieldTop; y < shieldTop + shieldHeight; y++) {
  const progress = (y - shieldTop) / shieldHeight;
  let halfW;
  if (progress < 0.65) {
    halfW = shieldWidth / 2;
  } else {
    // Taper to point
    const taperProgress = (progress - 0.65) / 0.35;
    halfW = (shieldWidth / 2) * (1 - taperProgress);
  }
  // Color gradient: lighter blue at top → darker at bottom
  const cr = Math.round(40 + (20 * progress));
  const cg = Math.round(100 + (50 * (1 - progress)));
  const cb = Math.round(180 + (40 * (1 - progress)));
  for (let x = Math.floor(shieldCx - halfW); x <= Math.ceil(shieldCx + halfW); x++) {
    setPixel(x, y, cr, cg, cb);
  }
}

// Inner shield highlight (white border effect)
const borderW = 12;
for (let y = shieldTop + borderW; y < shieldTop + shieldHeight - borderW * 2; y++) {
  const progress = (y - shieldTop) / shieldHeight;
  let halfW;
  if (progress < 0.65) {
    halfW = shieldWidth / 2 - borderW;
  } else {
    const taperProgress = (progress - 0.65) / 0.35;
    halfW = (shieldWidth / 2) * (1 - taperProgress) - borderW;
  }
  if (halfW < 0) continue;
  // Just draw left and right edge pixels (border outline)
  for (let t = 0; t < 4; t++) {
    setPixel(Math.floor(shieldCx - halfW) + t, y, 200, 220, 255, 120);
    setPixel(Math.ceil(shieldCx + halfW) - t, y, 200, 220, 255, 120);
  }
}

// Checkmark inside shield — white/green
const checkStartX = 340;
const checkStartY = 500;
const checkMidX = 470;
const checkMidY = 620;
const checkEndX = 690;
const checkEndY = 370;
const checkThick = 48;

// Draw thick line segments for checkmark
function drawThickLine(x0, y0, x1, y1, thickness, r, g, b) {
  const dx = x1 - x0;
  const dy = y1 - y0;
  const len = Math.sqrt(dx * dx + dy * dy);
  const steps = Math.ceil(len);
  for (let s = 0; s <= steps; s++) {
    const t = s / steps;
    const cx = x0 + dx * t;
    const cy = y0 + dy * t;
    fillCircle(cx, cy, thickness / 2, r, g, b);
  }
}

// Green checkmark
drawThickLine(checkStartX, checkStartY, checkMidX, checkMidY, checkThick, 80, 220, 120);
drawThickLine(checkMidX, checkMidY, checkEndX, checkEndY, checkThick, 80, 220, 120);

// "RET" text at bottom — simple block letters
const textY = 780;
const textScale = 5;
const letterW = 10 * textScale;
const letterH = 14 * textScale;
const gap = 4 * textScale;
const totalTextW = 3 * letterW + 2 * gap;
const textStartX = Math.floor((SIZE - totalTextW) / 2);

// Simple bitmap font for R, E, T (each 10x14 grid)
const letters = {
  R: [
    '########  ',
    '##    ## ',
    '##    ## ',
    '##    ## ',
    '########  ',
    '## ##    ',
    '##  ##   ',
    '##   ##  ',
    '##    ## ',
  ],
  E: [
    '#########',
    '##       ',
    '##       ',
    '##       ',
    '#######  ',
    '##       ',
    '##       ',
    '##       ',
    '#########',
  ],
  T: [
    '#########',
    '   ##    ',
    '   ##    ',
    '   ##    ',
    '   ##    ',
    '   ##    ',
    '   ##    ',
    '   ##    ',
    '   ##    ',
  ],
};

function drawLetter(letter, startX, startY, scale, r, g, b) {
  const rows = letters[letter];
  if (!rows) return;
  const rowH = Math.floor(letterH / rows.length);
  for (let row = 0; row < rows.length; row++) {
    for (let col = 0; col < rows[row].length; col++) {
      if (rows[row][col] === '#') {
        fillRect(
          startX + col * scale,
          startY + row * rowH,
          scale,
          rowH,
          r, g, b
        );
      }
    }
  }
}

drawLetter('R', textStartX, textY, textScale, 255, 255, 255);
drawLetter('E', textStartX + letterW + gap, textY, textScale, 255, 255, 255);
drawLetter('T', textStartX + 2 * (letterW + gap), textY, textScale, 255, 255, 255);

// ── Write PNG ──
const png = createPNG(SIZE, SIZE, pixels);
fs.writeFileSync(path.join(ASSETS, 'icon.png'), png);
console.log('Created assets/icon.png (1024x1024)');
