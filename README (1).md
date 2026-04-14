# DeepFree Web SDK

**Cryptographic carrier authentication for live voice calls.**

DeepFree embeds a time-varying HMAC-derived signal into audio to verify speaker identity. AI voice clones cannot replicate it. Neither can recorded audio. The guarantee is cryptographic, not probabilistic.

[![npm version](https://img.shields.io/npm/v/deepfree.svg)](https://www.npmjs.com/package/deepfree)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## How it works

1. A rolling HMAC-SHA256 signal is derived from the user's enrolled device key and the current 2-second time window
2. The signal is embedded into the outgoing audio stream at -30 dBFS (inaudible)
3. The receiving server scores the audio using phase-coherence analysis
4. Legitimate callers score ~0.87. AI voice clones score ~0.12

A voice clone — no matter how perfect — cannot replicate the carrier without the enrolled device credential.

---

## Installation

```bash
npm install deepfree
```

Or via CDN:

```html
<script src="https://deepfree.app/sdk/deepfree.js"></script>
```

---

## Quick start

```javascript
import DeepFree from 'deepfree';

const df = new DeepFree({
  backendUrl: 'https://your-deepfree-backend.com',
  apiKey: 'df_your_api_key',
});

// Register a user (first time only)
await df.register({
  username: 'alice',
  email:    'alice@example.com',
});

// Or restore from a previous session
await df.restoreCredentials();

// Request mic and start embedding the carrier
const stream = await df.requestMic();
const authenticatedStream = await df.startAuth(stream);

// Route authenticatedStream to WebRTC — it contains the embedded carrier
// peerConnection.addTrack(authenticatedStream.getAudioTracks()[0]);

// Listen for verification results
df.on('score', ({ confidence, verified, status }) => {
  console.log(`Confidence: ${Math.round(confidence * 100)}% — ${status}`);
});

df.on('verified', ({ username }) => {
  console.log(`✓ Verified: ${username}`);
});

df.on('error', ({ message, recoverable }) => {
  if (!recoverable) console.error('Fatal:', message);
});

// Stop when the call ends
await df.stopAuth();
```

---

## WebRTC integration

```javascript
const pc = new RTCPeerConnection(iceConfig);

const micStream    = await df.requestMic();
const authStream   = await df.startAuth(micStream, { sessionId });

// Add the carrier-embedded track to WebRTC — NOT the raw mic stream
authStream.getAudioTracks().forEach(track => {
  pc.addTrack(track, authStream);
});
```

---

## API

### `new DeepFree(options)`

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `backendUrl` | string | ✓ | URL of your DeepFree backend |
| `apiKey` | string | | API key (sent as `X-Api-Key` header) |
| `debug` | boolean | | Log debug info to console |

---

### Identity

#### `df.register(options)` → `Promise<credentials>`
Register a new user and enroll their first device.

```javascript
const creds = await df.register({
  username:   'alice',
  email:      'alice@example.com',
  phone:      '+12125551234',   // optional, for SMS challenge codes
  deviceName: 'Chrome Browser', // optional
  persist:    true,              // save to localStorage (default: true)
});
```

#### `df.restoreCredentials(storageKey?)` → `Promise<boolean>`
Restore credentials from localStorage. Returns `true` if found.

#### `df.loadCredentials(credentials)` → `Promise<DeepFree>`
Load credentials directly (e.g. from your own storage).

#### `df.validateCredentials()` → `Promise<boolean>`
Check stored credentials are still valid against the backend.

#### `df.getIdentity()` → `{ username, deviceName } | null`
Return the current identity, or `null` if not registered.

---

### Audio pipeline

#### `df.requestMic()` → `Promise<MediaStream>`
Request microphone access.

#### `df.startAuth(stream, options?)` → `Promise<MediaStream>`
Start embedding the carrier. Returns a new `MediaStream` with the carrier mixed in — route **this stream** to WebRTC, not the original.

| Option | Type | Description |
|--------|------|-------------|
| `sessionId` | string | From `createCallSession()` |

#### `df.stopAuth()` → `Promise<void>`
Stop authentication and release all audio resources.

#### `df.setMuted(muted)` → `void`
Mute/unmute the carrier embedding without stopping auth.

#### `df.setWebRTCMode(enabled)` → `void`
Enable Opus codec compensation. The SDK auto-detects this from score feedback, but calling this upfront skips the detection delay.

---

### Call sessions

#### `df.createCallSession(roomId?)` → `Promise<session>`
Generate a challenge code and send it to the user via email/SMS.

```javascript
const session = await df.createCallSession(roomId);
// session.session_id — pass to startAuth
// session.challenge_code — user reads this aloud to the agent
```

---

### Events

```javascript
df.on('score',         ({ confidence, verified, status, identityMatch, deviceMatch }) => {});
df.on('verified',      ({ username, confidence }) => {});
df.on('error',         ({ message, type, recoverable }) => {});
df.on('started',       ({ username }) => {});
df.on('stopped',       () => {});
df.on('recovering',    ({ attempt, maxRetries, delayMs }) => {});
df.on('recovered',     () => {});
df.on('window',        ({ timeWindow }) => {});
df.on('opus_detected', ({ averageScore, newAmplitude }) => {});
```

---

### Error recovery

The SDK automatically recovers from:
- AudioWorklet processor crashes
- Microphone disconnection
- Browser audio context suspension
- Transient network failures (3 retries with backoff)

Recovery uses exponential backoff: 1s, 2s, 4s, 8s, 16s (max 5 attempts).

---

## Security

- Carrier signal derived from HMAC-SHA256 over enrolled device key + 2-second time window
- Voice clones score ~0.12 vs legitimate callers ~0.87 (7× separation)
- Replay attacks fail — the carrier changes every 2 seconds
- Carrier stripping is infeasible without knowing the HMAC key
- Patent pending (US Provisional 2025)

See the [DeepFree paper](https://deepfree.app) for full security analysis.

---

## Browser support

Requires `AudioWorklet`, `Web Crypto API`, and `getUserMedia` — available in all modern browsers (Chrome 66+, Firefox 76+, Safari 14.1+, Edge 79+).

---

## License

MIT — see [LICENSE](LICENSE)

For commercial licensing and enterprise support: [hello@deepfree.app](mailto:hello@deepfree.app)
