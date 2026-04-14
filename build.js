/**
 * DeepFree SDK build script
 * Generates: dist/deepfree.js (UMD), dist/deepfree.esm.js (ESM), dist/deepfree.min.js (minified)
 * Run: node build.js
 */

const fs   = require('fs');
const path = require('path');

const src     = fs.readFileSync(path.join(__dirname, '..', 'deepfree.js'), 'utf8');
const distDir = path.join(__dirname, 'dist');

if (!fs.existsSync(distDir)) fs.mkdirSync(distDir, { recursive: true });

// ── 1. UMD build (already in this format) ────────────────────────────────────
fs.writeFileSync(path.join(distDir, 'deepfree.js'), src);
console.log('✓ dist/deepfree.js (UMD)');

// ── 2. ESM build ─────────────────────────────────────────────────────────────
// Strip the UMD wrapper and export as ES module
const esmCore = src
  .replace(
    /^\(function \(root, factory\) \{[\s\S]*?}\(typeof self[\s\S]*?, function \(\) \{/,
    "'use strict';\n\nexport default (function () {"
  )
  .replace(/\s*return DeepFree;\s*\}\)\);\s*$/, '\n  return DeepFree;\n})();');

fs.writeFileSync(path.join(distDir, 'deepfree.esm.js'), esmCore);
console.log('✓ dist/deepfree.esm.js (ESM)');

// ── 3. Minified build (basic minification without external deps) ──────────────
const minified = src
  .replace(/\/\*[\s\S]*?\*\//g, '')     // remove block comments
  .replace(/\/\/[^\n]*/g, '')            // remove line comments
  .replace(/\n\s*\n/g, '\n')            // collapse blank lines
  .replace(/^\s+/gm, '')                // remove leading whitespace per line
  .replace(/\s{2,}/g, ' ')              // collapse multiple spaces
  .trim();

// Add the license banner back
const banner = `/*! DeepFree SDK v1.0.0 | MIT License | deepfree.app */\n`;
fs.writeFileSync(path.join(distDir, 'deepfree.min.js'), banner + minified);
console.log('✓ dist/deepfree.min.js (minified)');

// ── 4. TypeScript declarations ────────────────────────────────────────────────
const dts = fs.readFileSync(path.join(__dirname, 'deepfree.d.ts'), 'utf8');
fs.writeFileSync(path.join(distDir, 'deepfree.d.ts'), dts);
console.log('✓ dist/deepfree.d.ts (TypeScript)');

console.log('\nBuild complete → dist/');
