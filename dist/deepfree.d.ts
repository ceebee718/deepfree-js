/**
 * DeepFree Web SDK - TypeScript Declarations
 * Cryptographic carrier authentication for live voice calls.
 */

export interface DeepFreeOptions {
  /** URL of your DeepFree backend (required) */
  backendUrl: string;
  /** API key for your backend — sent as X-Api-Key header */
  apiKey?: string;
  /** Log debug info to console */
  debug?: boolean;
}

export interface DeepFreeIdentity {
  username: string;
  deviceName: string | null;
}

export interface DeepFreeCredentials {
  username: string;
  user_key: string;
  device_id: string;
  device_key: string;
  device_name: string;
}

export interface RegisterOptions {
  username: string;
  email: string;
  phone?: string;
  deviceName?: string;
  /** Store credentials in localStorage (default: true) */
  persist?: boolean;
}

export interface StartAuthOptions {
  sessionId?: string;
}

export interface ScoreResult {
  confidence: number;
  carrierScore: number;
  timingScore: number | null;
  timingVerified: boolean | null;
  identityMatch: boolean;
  deviceMatch: boolean;
  status: string;
  statusLabel: string;
  verified: boolean;
  windowOffset: number;
  username: string | null;
  deviceName: string | null;
  challengeConfirmed: boolean;
  timeWindow: number;
}

export interface ErrorEvent {
  message: string;
  type:
    | 'verify_failed'
    | 'processor_error'
    | 'mic_ended'
    | 'context_suspended'
    | 'context_closed'
    | 'backend_unreachable'
    | 'unrecoverable';
  recoverable: boolean;
  retries?: number;
}

export interface RecoveringEvent {
  attempt: number;
  maxRetries: number;
  delayMs: number;
}

export interface OpusDetectedEvent {
  averageScore: number;
  newAmplitude: number;
}

export interface CallSessionResult {
  session_id: string;
  challenge_code: string;
  room_id: string;
  username: string;
  delivered: {
    email: boolean;
    sms: boolean;
    dev_code?: string;
  };
}

export type DeepFreeEventMap = {
  score:         ScoreResult;
  verified:      ScoreResult;
  error:         ErrorEvent;
  started:       { username: string };
  stopped:       Record<string, never>;
  recovering:    RecoveringEvent;
  recovered:     { attempt: number };
  window:        { timeWindow: number };
  opus_detected: OpusDetectedEvent;
};

export declare class DeepFree {
  static version: string;
  static WINDOW_SEC: number;
  static CHUNK_FRAMES: number;
  static SAMPLE_RATE: number;
  static CARRIER_BINS: number;

  constructor(options: DeepFreeOptions);

  // ── Events ──────────────────────────────────────────────────────────────
  on<K extends keyof DeepFreeEventMap>(
    event: K,
    callback: (data: DeepFreeEventMap[K]) => void
  ): this;

  off<K extends keyof DeepFreeEventMap>(
    event: K,
    callback: (data: DeepFreeEventMap[K]) => void
  ): this;

  // ── Identity ─────────────────────────────────────────────────────────────
  register(options: RegisterOptions): Promise<DeepFreeCredentials>;
  loadCredentials(credentials: DeepFreeCredentials): Promise<this>;
  restoreCredentials(storageKey?: string): Promise<boolean>;
  validateCredentials(): Promise<boolean>;
  getIdentity(): DeepFreeIdentity | null;

  // ── Call session ──────────────────────────────────────────────────────────
  createCallSession(roomId?: string): Promise<CallSessionResult>;

  // ── Audio pipeline ────────────────────────────────────────────────────────
  requestMic(): Promise<MediaStream>;
  startAuth(stream: MediaStream, options?: StartAuthOptions): Promise<MediaStream>;
  stopAuth(): Promise<void>;
  setMuted(muted: boolean): void;
  setWebRTCMode(enabled: boolean): void;

  // ── One-shot verify ───────────────────────────────────────────────────────
  verifyChunk(samples: Float32Array, timeWindow?: number): Promise<ScoreResult | undefined>;

  // ── Utility ───────────────────────────────────────────────────────────────
  isRunning(): boolean;
  health(): Promise<{ status: string; time: number }>;
}

export default DeepFree;
