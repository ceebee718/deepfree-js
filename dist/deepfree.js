/**
 * DeepFree Web SDK v1.0.0
 * Cryptographic carrier authentication for live voice calls.
 *
 * Usage:
 *   <script src="deepfree.js"></script>
 *   const df = new DeepFree({ apiKey: 'your-api-key', backendUrl: 'https://your-backend.com' });
 *   await df.register({ username: 'alice', email: 'alice@example.com' });
 *   await df.startAuth(mediaStream);
 *   df.on('score', ({ confidence, status, verified }) => console.log(verified));
 *   await df.stopAuth();
 */

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.DeepFree = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ─── CONSTANTS (must match backend) ──────────────────────────────────────
  const WINDOW_SEC   = 2;
  const CHUNK_FRAMES = 4096;
  const SAMPLE_RATE  = 44100;
  const CARRIER_AMP        = 0.03;   // -30 dBFS — baseline (direct audio)
  const CARRIER_AMP_WEBRTC = 0.048;  // -26 dBFS — compensates Opus codec degradation
  const CARRIER_BINS = 16;
  const SEND_EVERY_N = 2;
  const MIN_FREQ_HZ  = 1000;
  const MAX_FREQ_HZ  = 4000;

  // ─── CRYPTO HELPERS ──────────────────────────────────────────────────────

  /**
   * Derive combined secret from user key + device key.
   * Mirrors backend derive_combined_secret exactly.
   * @param {string} userKey
   * @param {string} deviceKey
   * @returns {Promise<string>} hex string
   */
  async function combinedSecret(userKey, deviceKey) {
    const enc  = new TextEncoder();
    const data = enc.encode(`${userKey}:${deviceKey}`);
    const buf  = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Derive timing offset from credentials.
   * Range: -400ms to +400ms. Mirrors backend derive_timing_offset.
   * @param {string} userKey
   * @param {string} deviceKey
   * @returns {Promise<number>} offset in ms
   */
  async function deriveTimingOffset(userKey, deviceKey) {
    const enc  = new TextEncoder();
    const data = enc.encode(`timing:${userKey}:${deviceKey}`);
    const buf  = await crypto.subtle.digest('SHA-256', data);
    const arr  = new Uint8Array(buf);
    const raw  = (arr[0] << 8) | arr[1];
    return Math.round((raw / 65535) * 800 - 400);
  }

  /**
   * Derive the HMAC-SHA256 carrier signal for a given (secret, timeWindow).
   * Mirrors backend derive_carrier exactly.
   * @param {string} secret - combined hex secret
   * @param {number} timeWindow - floor(unix_seconds / WINDOW_SEC)
   * @param {number} sampleRate
   * @param {number} count - number of samples
   * @returns {Promise<Float32Array>}
   */
  async function deriveCarrier(secret, timeWindow, sampleRate, count, amp) {
    amp = amp || CARRIER_AMP;
    const enc     = new TextEncoder();
    const keyData = enc.encode(secret);
    const msg     = enc.encode(String(timeWindow));

    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, msg);
    const sigArr = new Uint8Array(sigBuf);

    const minBin = Math.round(MIN_FREQ_HZ * count / sampleRate);
    const maxBin = Math.round(MAX_FREQ_HZ * count / sampleRate);
    const range  = maxBin - minBin;

    const carrier = new Float32Array(count);
    for (let i = 0; i < CARRIER_BINS; i++) {
      const byteOffset = (i * 2) % 32;
      const binIdx = minBin + (sigArr[byteOffset] % range);
      const phase  = (sigArr[(byteOffset + 1) % 32] / 255) * 2 * Math.PI;
      const freq   = binIdx * sampleRate / count;
      for (let n = 0; n < count; n++) {
        carrier[n] += Math.cos(2 * Math.PI * freq * n / sampleRate + phase);
      }
    }

    let maxAbs = 0;
    for (let n = 0; n < count; n++) maxAbs = Math.max(maxAbs, Math.abs(carrier[n]));
    if (maxAbs > 0) {
      for (let n = 0; n < count; n++) carrier[n] = carrier[n] / maxAbs * amp;
    }

    return carrier;
  }

  /**
   * Get current TOTP-style time window.
   * @returns {number}
   */
  function getTimeWindow() {
    return Math.floor(Date.now() / 1000 / WINDOW_SEC);
  }

  // ─── DEEPFREE CLASS ──────────────────────────────────────────────────────

  /**
   * DeepFree SDK
   * @param {Object} options
   * @param {string} options.backendUrl - URL of your DeepFree backend (required)
   * @param {string} [options.apiKey]  - API key for your backend (optional, sent as X-Api-Key header)
   * @param {boolean} [options.debug]  - Log debug info to console
   */
  function DeepFree(options) {
    if (!options || !options.backendUrl) {
      throw new Error('DeepFree: backendUrl is required');
    }

    this._backendUrl = options.backendUrl.replace(/\/$/, '');
    this._apiKey     = options.apiKey || '';
    this._debug      = options.debug  || false;

    // Auth state
    this._user       = null;   // { username, user_key }
    this._device     = null;   // { device_id, device_key, device_name }
    this._sessionId  = null;

    // Audio pipeline
    this._audioCtx      = null;
    this._sourceNode    = null;
    this._processorNode = null;
    this._stream        = null;
    this._running       = false;

    // Carrier state
    this._carrier        = null;
    this._carrierWindow  = -1;
    this._embedOffset    = 0;
    this._chunkBuffer    = new Float32Array(0);
    this._chunksQueued   = 0;
    this._timingOffset   = 0;

    // Opus compensation
    this._opusMode    = false;  // auto-detected from score feedback
    this._scoreWindow = [];     // rolling window of recent scores

    // Event listeners
    this._listeners = {};

    this._log('DeepFree SDK initialized', { backendUrl: this._backendUrl });
  }

  // ─── EVENT EMITTER ───────────────────────────────────────────────────────

  /**
   * Register an event listener.
   * Events: 'score', 'verified', 'error', 'started', 'stopped', 'window'
   * @param {string} event
   * @param {Function} callback
   * @returns {DeepFree} for chaining
   */
  DeepFree.prototype.on = function (event, callback) {
    if (!this._listeners[event]) this._listeners[event] = [];
    this._listeners[event].push(callback);
    return this;
  };

  /**
   * Remove an event listener.
   * @param {string} event
   * @param {Function} callback
   * @returns {DeepFree} for chaining
   */
  DeepFree.prototype.off = function (event, callback) {
    if (!this._listeners[event]) return this;
    this._listeners[event] = this._listeners[event].filter(fn => fn !== callback);
    return this;
  };

  DeepFree.prototype._emit = function (event, data) {
    const fns = this._listeners[event] || [];
    fns.forEach(fn => { try { fn(data); } catch (e) { console.error('DeepFree event error:', e); } });
  };

  DeepFree.prototype._log = function (...args) {
    if (this._debug) console.log('[DeepFree]', ...args);
  };

  // ─── HTTP HELPERS ────────────────────────────────────────────────────────

  DeepFree.prototype._headers = function () {
    const h = { 'Content-Type': 'application/json' };
    if (this._apiKey) h['X-Api-Key'] = this._apiKey;
    return h;
  };

  DeepFree.prototype._post = async function (path, body) {
    const res = await fetch(`${this._backendUrl}${path}`, {
      method:  'POST',
      headers: this._headers(),
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  };

  DeepFree.prototype._get = async function (path) {
    const res = await fetch(`${this._backendUrl}${path}`, {
      headers: this._headers(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  };

  // ─── IDENTITY MANAGEMENT ─────────────────────────────────────────────────

  /**
   * Register a new user and enroll their first device.
   * Stores credentials in memory (and optionally localStorage).
   * @param {Object} opts
   * @param {string} opts.username
   * @param {string} opts.email
   * @param {string} [opts.phone]
   * @param {string} [opts.deviceName]
   * @param {boolean} [opts.persist] - store in localStorage (default: true)
   * @returns {Promise<{username, user_key, device_id, device_key}>}
   */
  DeepFree.prototype.register = async function (opts) {
    const data = await this._post('/register_full', {
      username:    opts.username,
      email:       opts.email,
      phone:       opts.phone       || '',
      device_name: opts.deviceName  || 'DeepFree SDK Device',
    });

    this._user   = { username: data.username, user_key: data.user_key };
    this._device = { device_id: data.device_id, device_key: data.device_key, device_name: data.device_name };

    this._timingOffset = await deriveTimingOffset(data.user_key, data.device_key);

    if (opts.persist !== false) {
      this._persistCredentials();
    }

    this._log('Registered', this._user.username);
    return data;
  };

  /**
   * Load stored credentials (from a previous register() call).
   * @param {Object} creds - { username, user_key, device_id, device_key, device_name }
   * @returns {Promise<DeepFree>} for chaining
   */
  DeepFree.prototype.loadCredentials = async function (creds) {
    this._user   = { username: creds.username, user_key: creds.user_key };
    this._device = { device_id: creds.device_id, device_key: creds.device_key, device_name: creds.device_name };
    this._timingOffset = await deriveTimingOffset(creds.user_key, creds.device_key);
    this._log('Credentials loaded for', this._user.username);
    return this;
  };

  /**
   * Restore credentials from localStorage (if previously persisted).
   * @param {string} [storageKey] - localStorage key (default: 'deepfree_credentials')
   * @returns {Promise<boolean>} true if credentials were found and loaded
   */
  DeepFree.prototype.restoreCredentials = async function (storageKey) {
    const key = storageKey || 'deepfree_credentials';
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return false;
      const creds = JSON.parse(raw);
      await this.loadCredentials(creds);
      return true;
    } catch (e) {
      this._log('Failed to restore credentials:', e.message);
      return false;
    }
  };

  DeepFree.prototype._persistCredentials = function (storageKey) {
    const key = storageKey || 'deepfree_credentials';
    try {
      localStorage.setItem(key, JSON.stringify({
        username:    this._user.username,
        user_key:    this._user.user_key,
        device_id:   this._device.device_id,
        device_key:  this._device.device_key,
        device_name: this._device.device_name,
      }));
    } catch (e) {
      this._log('localStorage unavailable, credentials not persisted');
    }
  };

  /**
   * Validate stored credentials against the backend.
   * @returns {Promise<boolean>}
   */
  DeepFree.prototype.validateCredentials = async function () {
    if (!this._user) return false;
    try {
      const data = await this._get(`/me/${this._user.username}`);
      return data.valid === true;
    } catch (e) {
      return false;
    }
  };

  /**
   * Returns current identity info, or null if not registered.
   * @returns {{ username: string, deviceName: string } | null}
   */
  DeepFree.prototype.getIdentity = function () {
    if (!this._user) return null;
    return {
      username:   this._user.username,
      deviceName: this._device ? this._device.device_name : null,
    };
  };

  // ─── CALL SESSION ────────────────────────────────────────────────────────

  /**
   * Create a call session. Generates a challenge code and sends it
   * to the user via email/SMS. Returns session_id for use in startAuth().
   * @param {string} roomId
   * @returns {Promise<{ session_id, challenge_code, delivered }>}
   */
  DeepFree.prototype.createCallSession = async function (roomId) {
    if (!this._user) throw new Error('DeepFree: not registered — call register() or loadCredentials() first');
    const data = await this._post('/create_call_session', {
      username: this._user.username,
      room_id:  roomId || '',
    });
    this._sessionId = data.session_id;
    this._log('Call session created', data.session_id);
    return data;
  };

  // ─── AUDIO PIPELINE ──────────────────────────────────────────────────────

  /**
   * Start embedding the cryptographic carrier into a MediaStream and
   * sending verification chunks to the backend.
   *
   * @param {MediaStream} stream - from getUserMedia()
   * @param {Object} [opts]
   * @param {string} [opts.sessionId] - from createCallSession() (optional)
   * @returns {Promise<MediaStream>} - new stream with carrier embedded (route this to WebRTC)
   */
  // ─── AUDIOWORKLET CODE (runs in dedicated audio thread) ──────────────────
  const WORKLET_CODE = `
class CarrierEmbedderProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this._carrier     = null;
    this._offset      = 0;
    this._muted       = false;
    this._verifyBuf   = [];
    this._accumulated = 0;
    this._sendEvery   = 4096;

    this.port.onmessage = (e) => {
      if (e.data.type === 'carrier') {
        this._carrier = e.data.carrier;
        this._offset  = 0;
      }
      if (e.data.type === 'mute') {
        this._muted = e.data.muted;
      }
    };
  }

  process(inputs, outputs) {
    const input  = inputs[0][0];
    const output = outputs[0][0];
    if (!input) return true;

    for (let i = 0; i < input.length; i++) {
      const cs = (this._carrier && !this._muted)
        ? this._carrier[(this._offset + i) % this._carrier.length]
        : 0;
      output[i] = this._muted ? 0 : input[i] + cs;
    }
    if (this._carrier) {
      this._offset = (this._offset + input.length) % this._carrier.length;
    }

    if (!this._muted && input.length > 0) {
      for (let i = 0; i < input.length; i++) this._verifyBuf.push(input[i]);
      this._accumulated += input.length;
      if (this._accumulated >= this._sendEvery) {
        this.port.postMessage({
          type:    'verify_chunk',
          samples: new Float32Array(this._verifyBuf.splice(0, this._sendEvery)),
        });
        this._accumulated -= this._sendEvery;
      }
    }
    return true;
  }
}
registerProcessor('carrier-embedder', CarrierEmbedderProcessor);
`;

  DeepFree.prototype.startAuth = async function (stream, opts) {
    if (this._running) throw new Error('DeepFree: already running — call stopAuth() first');
    if (!this._user)   throw new Error('DeepFree: not registered — call register() or loadCredentials() first');

    opts = opts || {};
    if (opts.sessionId) this._sessionId = opts.sessionId;

    this._stream        = stream;
    this._carrierWindow = -1;
    this._chunksQueued  = 0;
    this._lastVerifyTs  = 0;
    this._recovering    = false;
    this._retryCount    = 0;

    await this._buildAudioPipeline(stream);

    this._running = true;
    this._log('Auth started (AudioWorklet) for', this._user.username);
    this._emit('started', { username: this._user.username });

    return this._destNode.stream;
  };

  // ─── INTERNAL: build (or rebuild) the audio pipeline ─────────────────────
  DeepFree.prototype._buildAudioPipeline = async function (stream) {
    const self = this;

    this._audioCtx   = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: SAMPLE_RATE });
    this._sourceNode = this._audioCtx.createMediaStreamSource(stream);
    this._destNode   = this._audioCtx.createMediaStreamDestination();

    // Load AudioWorklet from Blob URL — no separate file needed
    const blob    = new Blob([WORKLET_CODE], { type: 'application/javascript' });
    const blobUrl = URL.createObjectURL(blob);
    await this._audioCtx.audioWorklet.addModule(blobUrl);
    URL.revokeObjectURL(blobUrl);

    this._processorNode = new AudioWorkletNode(this._audioCtx, 'carrier-embedder', {
      numberOfInputs:     1,
      numberOfOutputs:    1,
      outputChannelCount: [1],
    });

    // Detect worklet crash — AudioWorkletNode fires 'processorerror' on failure
    this._processorNode.onprocessorerror = function (e) {
      self._log('AudioWorklet processor error — attempting recovery:', e);
      self._emit('error', { message: 'Audio processor error', type: 'processor_error', recoverable: true });
      if (self._running) self._attemptRecovery();
    };

    // Push carrier every 500ms — update on window change
    async function updateCarrier() {
      if (!self._running || !self._processorNode) return;
      const tw = getTimeWindow();
      self._emit('window', { timeWindow: tw });
      if (tw !== self._carrierWindow) {
        try {
          const seed = self._device
            ? await combinedSecret(self._user.user_key, self._device.device_key)
            : self._user.user_key;
          const amp     = self._opusMode ? CARRIER_AMP_WEBRTC : CARRIER_AMP;
          const carrier = await deriveCarrier(seed, tw, SAMPLE_RATE, CHUNK_FRAMES, amp);
          self._log('Carrier amp: ' + amp + (self._opusMode ? ' (Opus-boosted)' : ' (baseline)'));
          if (self._processorNode) {
            self._processorNode.port.postMessage({ type: 'carrier', carrier });
          }
          self._carrierWindow = tw;
          self._log('Window ' + tw + ' — carrier sent to worklet');
        } catch (e) {
          self._log('Carrier update error:', e.message);
        }
      }
    }

    await updateCarrier();
    if (this._carrierTimer) clearInterval(this._carrierTimer);
    this._carrierTimer = setInterval(updateCarrier, 500);

    // Receive verify chunks back from worklet
    const VERIFY_EVERY_MS = 2200;
    this._processorNode.port.onmessage = function (e) {
      if (e.data.type !== 'verify_chunk') return;
      const now = Date.now();
      if (now - self._lastVerifyTs > VERIFY_EVERY_MS) {
        self._lastVerifyTs = now;
        self._sendChunk(e.data.samples, getTimeWindow());
      }
    };

    // Connect graph: mic → worklet → RTC destination
    this._sourceNode.connect(this._processorNode);
    this._processorNode.connect(this._destNode);

    // Watch for mic track ending (user unplugs mic, browser revokes access)
    const tracks = stream.getAudioTracks();
    if (tracks.length > 0) {
      tracks[0].onended = function () {
        self._log('Mic track ended — attempting recovery');
        self._emit('error', { message: 'Microphone disconnected', type: 'mic_ended', recoverable: true });
        if (self._running) self._attemptRecovery();
      };
    }

    // Watch for AudioContext being suspended (browser tab backgrounded, etc.)
    this._audioCtx.onstatechange = function () {
      if (!self._running) return;
      self._log('AudioContext state:', self._audioCtx.state);
      if (self._audioCtx.state === 'suspended') {
        self._audioCtx.resume().catch(() => {});
        self._emit('error', { message: 'Audio context suspended — resuming', type: 'context_suspended', recoverable: true });
      } else if (self._audioCtx.state === 'closed') {
        self._emit('error', { message: 'Audio context closed', type: 'context_closed', recoverable: true });
        if (self._running) self._attemptRecovery();
      }
    };
  };

  // ─── RECOVERY ────────────────────────────────────────────────────────────
  const MAX_RETRIES    = 5;
  const RETRY_BASE_MS  = 1000;

  DeepFree.prototype._attemptRecovery = async function () {
    if (this._recovering) return;
    if (this._retryCount >= MAX_RETRIES) {
      this._log('Max retries reached — stopping');
      this._emit('error', { message: 'Could not recover audio pipeline after ' + MAX_RETRIES + ' attempts', type: 'unrecoverable', recoverable: false });
      this.stopAuth();
      return;
    }

    this._recovering = true;
    this._retryCount++;
    const delay = RETRY_BASE_MS * Math.pow(2, this._retryCount - 1); // 1s, 2s, 4s, 8s, 16s
    this._log('Recovery attempt ' + this._retryCount + '/' + MAX_RETRIES + ' in ' + delay + 'ms');
    this._emit('recovering', { attempt: this._retryCount, maxRetries: MAX_RETRIES, delayMs: delay });

    await new Promise(r => setTimeout(r, delay));
    if (!this._running) return;

    // Tear down old pipeline nodes
    try { if (this._processorNode) this._processorNode.disconnect(); } catch (_) {}
    try { if (this._sourceNode)    this._sourceNode.disconnect(); }    catch (_) {}
    try { if (this._audioCtx)      await this._audioCtx.close(); }    catch (_) {}
    this._processorNode = null;
    this._sourceNode    = null;
    this._audioCtx      = null;
    this._carrierWindow = -1;

    try {
      // Re-request mic if the track ended
      let stream = this._stream;
      const tracks = stream ? stream.getAudioTracks() : [];
      if (!tracks.length || tracks[0].readyState === 'ended') {
        this._log('Re-requesting mic access');
        stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        this._stream = stream;
      }

      await this._buildAudioPipeline(stream);
      this._recovering = false;
      this._retryCount = 0;
      this._log('Recovery successful');
      this._emit('recovered', { attempt: this._retryCount });
    } catch (e) {
      this._log('Recovery failed:', e.message);
      this._recovering = false;
      this._attemptRecovery(); // try again
    }
  };

  /**
   * Mute/unmute the carrier embedding.
   * @param {boolean} muted
   */
  DeepFree.prototype.setMuted = function (muted) {
    if (this._processorNode) {
      this._processorNode.port.postMessage({ type: 'mute', muted });
    }
  };

  /**
   * Manually enable Opus compensation mode.
   * Call this if you know audio is going through WebRTC/Opus encoding.
   * The SDK also auto-detects this from score feedback, but calling this
   * upfront avoids the ~4 chunk detection delay.
   * @param {boolean} enabled
   */
  DeepFree.prototype.setWebRTCMode = function (enabled) {
    if (this._opusMode !== enabled) {
      this._opusMode    = enabled;
      this._carrierWindow = -1; // force carrier rebuild with new amplitude
      this._log('WebRTC/Opus mode ' + (enabled ? 'enabled' : 'disabled') + ' manually');
    }
  };

  /**
   * Stop authentication and release all audio resources.
   */
  DeepFree.prototype.stopAuth = async function () {
    this._running = false;

    if (this._carrierTimer)  { clearInterval(this._carrierTimer); this._carrierTimer  = null; }
    if (this._processorNode) { this._processorNode.disconnect();  this._processorNode = null; }
    if (this._sourceNode)    { this._sourceNode.disconnect();     this._sourceNode    = null; }
    if (this._destNode)      { this._destNode    = null; }
    if (this._audioCtx)      { await this._audioCtx.close();      this._audioCtx      = null; }

    this._carrierWindow = -1;
    this._chunksQueued  = 0;
    this._lastVerifyTs  = 0;

    this._log('Auth stopped');
    this._emit('stopped', {});
  };

















  // ─── VERIFICATION ────────────────────────────────────────────────────────

  DeepFree.prototype._sendChunk = async function (samples, timeWindow, _attempt) {
    _attempt = _attempt || 1;
    const MAX_VERIFY_RETRIES = 3;

    const bytes  = new Uint8Array(samples.buffer);
    let binary   = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    const b64    = btoa(binary);

    const body = {
      audio_b64:     b64,
      time_window:   timeWindow,
      sample_rate:   SAMPLE_RATE,
      username:      this._user    ? this._user.username    : '',
      device_id:     this._device  ? this._device.device_id : '',
      session_id:    this._sessionId || '',
      secret:        this._user    ? this._user.user_key    : 'demo_secret',
      chunk_sent_at: Date.now() + (this._timingOffset || 0),
    };

    try {
      const data = await this._post('/verify', body);

      // Successful response — reset backend retry counter
      this._backendRetries = 0;

      const score    = data.confidence_score ?? data.score ?? 0;
      const verified = data.status === 'verified_correct' ||
                       data.status === 'verified_agent_override';

      const result = {
        confidence:         score,
        carrierScore:       data.carrier_score  ?? score,
        timingScore:        data.timing_score    ?? null,
        timingVerified:     data.timing_verified ?? null,
        identityMatch:      data.identity_match,
        deviceMatch:        data.device_match,
        status:             data.status,
        statusLabel:        data.status_label,
        verified,
        windowOffset:       data.window_offset,
        username:           data.username,
        deviceName:         data.device_name,
        challengeConfirmed: data.challenge_confirmed,
        timeWindow,
      };

      this._emit('score', result);
      if (verified) this._emit('verified', result);
      this._log('score=' + (score * 100).toFixed(1) + '% status=' + data.status);

      // ── Opus auto-detection ─────────────────────────────────────────────
      // If scores are consistently below 0.80 (expected ~0.87 on clean path),
      // the signal is likely being degraded by Opus compression.
      // Switch to boosted amplitude and reset carrier so it takes effect immediately.
      this._scoreWindow.push(score);
      if (this._scoreWindow.length > 6) this._scoreWindow.shift();

      if (this._scoreWindow.length >= 4) {
        const avg = this._scoreWindow.reduce((a, b) => a + b, 0) / this._scoreWindow.length;
        const wasOpus = this._opusMode;

        if (!this._opusMode && avg < 0.72 && avg > 0.45) {
          // Scores depressed but not random — likely Opus degradation
          this._opusMode = true;
          this._carrierWindow = -1; // force carrier rebuild with boosted amp
          this._log('Opus degradation detected (avg=' + avg.toFixed(2) + ') — boosting carrier amplitude');
          this._emit('opus_detected', { averageScore: avg, newAmplitude: CARRIER_AMP_WEBRTC });
        } else if (this._opusMode && avg >= 0.80) {
          // Scores recovered — revert to baseline
          this._opusMode = false;
          this._carrierWindow = -1;
          this._log('Scores recovered (avg=' + avg.toFixed(2) + ') — reverting to baseline amplitude');
        }
      }

      return result;

    } catch (e) {
      this._log('Verify error (attempt ' + _attempt + '):', e.message);

      // Retry transient network errors with backoff
      if (_attempt < MAX_VERIFY_RETRIES && this._running) {
        const retryDelay = 500 * _attempt;
        this._log('Retrying verify in ' + retryDelay + 'ms');
        await new Promise(r => setTimeout(r, retryDelay));
        return this._sendChunk(samples, timeWindow, _attempt + 1);
      }

      // Max retries hit — emit error but don't crash the pipeline
      this._backendRetries = (this._backendRetries || 0) + 1;
      this._emit('error', {
        message:     e.message,
        type:        'verify_failed',
        recoverable: true,
        retries:     this._backendRetries,
      });

      // If backend has been unreachable for many consecutive chunks, warn
      if (this._backendRetries >= 5) {
        this._emit('error', {
          message:     'Backend unreachable for multiple consecutive chunks',
          type:        'backend_unreachable',
          recoverable: true,
        });
      }
    }
  };

  /**
   * One-shot verify: pass raw audio samples directly (without starting the full pipeline).
   * Useful for server-side style integration where you already have audio data.
   * @param {Float32Array} samples
   * @param {number} [timeWindow] - defaults to current window
   * @returns {Promise<Object>} verification result
   */
  DeepFree.prototype.verifyChunk = async function (samples, timeWindow) {
    const tw = timeWindow || getTimeWindow();
    return this._sendChunk(samples, tw);
  };

  // ─── UTILITY ─────────────────────────────────────────────────────────────

  /**
   * Request mic access and return a MediaStream.
   * Convenience wrapper around getUserMedia.
   * @returns {Promise<MediaStream>}
   */
  DeepFree.prototype.requestMic = async function () {
    return navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  };

  /**
   * Check if authentication is currently running.
   * @returns {boolean}
   */
  DeepFree.prototype.isRunning = function () {
    return this._running;
  };

  /**
   * Get backend health status.
   * @returns {Promise<{ status: string, time: number }>}
   */
  DeepFree.prototype.health = async function () {
    return this._get('/health');
  };

  // ─── STATIC ──────────────────────────────────────────────────────────────

  DeepFree.version = '1.0.0';
  DeepFree.WINDOW_SEC   = WINDOW_SEC;
  DeepFree.CHUNK_FRAMES = CHUNK_FRAMES;
  DeepFree.SAMPLE_RATE  = SAMPLE_RATE;
  DeepFree.CARRIER_BINS = CARRIER_BINS;

  return DeepFree;
}));
