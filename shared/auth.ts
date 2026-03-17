import { Database } from "bun:sqlite";

/**
 * Explicit Argon2id parameters — not relying on Bun defaults.
 * Single place to update, visible in code review.
 */
export const ARGON2_PARAMS = {
  algorithm: "argon2id" as const,
  memoryCost: 65536,
  timeCost: 3,
};

export interface SessionData {
  id: string;
  user_id: string;
  ip_address: string;
  user_agent: string;
  expires_at: string;
  absolute_expires_at: string;
  created_at: string;
}

/**
 * Hash a password with Argon2id using explicit params.
 */
export async function hashPassword(password: string): Promise<string> {
  return await Bun.password.hash(password, ARGON2_PARAMS);
}

/**
 * Verify a password against an Argon2id hash.
 * verify() auto-detects params from the hash string.
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await Bun.password.verify(password, hash);
}

/**
 * Create a session with 256-bit crypto-random ID.
 * 30-day sliding expiry + 90-day absolute hard cap.
 * user_agent capped at 512 chars.
 */
const MAX_SESSIONS_PER_USER = 10;

export function createSession(db: Database, userId: string, ip: string, userAgent: string): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const sessionId = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

  const cappedUA = userAgent.slice(0, 512);

  // Enforce session limit: max 10 active sessions per user
  const { count } = db.query(
    "SELECT COUNT(*) as count FROM sessions WHERE user_id = ? AND expires_at > datetime('now')"
  ).get(userId) as { count: number };

  if (count >= MAX_SESSIONS_PER_USER) {
    // Delete oldest sessions to make room for exactly 1 new one
    const excess = count - (MAX_SESSIONS_PER_USER - 1);
    db.run(
      `DELETE FROM sessions WHERE id IN (
        SELECT id FROM sessions WHERE user_id = ? AND expires_at > datetime('now')
        ORDER BY created_at ASC LIMIT ?
      )`,
      [userId, excess]
    );
  }

  db.run(
    `INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at, absolute_expires_at)
     VALUES (?, ?, ?, ?, datetime('now', '+30 days'), datetime('now', '+90 days'))`,
    [sessionId, userId, ip, cappedUA]
  );

  return sessionId;
}

/**
 * Get a session by ID. Returns null if expired (sliding or absolute).
 */
export function getSession(db: Database, sessionId: string): SessionData | null {
  return db.query(
    `SELECT id, user_id, ip_address, user_agent, expires_at, absolute_expires_at, created_at
     FROM sessions
     WHERE id = ? AND expires_at > datetime('now') AND absolute_expires_at > datetime('now')`
  ).get(sessionId) as SessionData | null;
}

/**
 * Refresh session sliding expiry, but ONLY when within last 25% of window
 * (< 7.5 days remaining) to avoid write-per-request amplification.
 */
export function refreshSessionExpiry(db: Database, sessionId: string): void {
  db.run(
    `UPDATE sessions SET expires_at = datetime('now', '+30 days')
     WHERE id = ? AND expires_at < datetime('now', '+7 days', '+12 hours')`,
    [sessionId]
  );
}

/**
 * Delete a session by ID.
 */
export function deleteSession(db: Database, sessionId: string): void {
  db.run("DELETE FROM sessions WHERE id = ?", [sessionId]);
}

/**
 * Delete all sessions for a user, optionally keeping one.
 */
export function deleteUserSessions(db: Database, userId: string, exceptSessionId?: string): void {
  if (exceptSessionId) {
    db.run("DELETE FROM sessions WHERE user_id = ? AND id != ?", [userId, exceptSessionId]);
  } else {
    db.run("DELETE FROM sessions WHERE user_id = ?", [userId]);
  }
}

/**
 * Log an authentication event to the audit table.
 * userId can be null for failed login attempts on unknown emails.
 * user_agent capped at 512 chars.
 */
export function logAuthEvent(
  db: Database,
  userId: string | null,
  event: string,
  ip: string,
  userAgent: string,
  metadata?: Record<string, unknown>
): void {
  const cappedUA = userAgent.slice(0, 512);
  const id = crypto.randomUUID();

  db.run(
    `INSERT INTO auth_events (id, user_id, event, ip_address, user_agent, metadata)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [id, userId, event, ip, cappedUA, metadata ? JSON.stringify(metadata) : null]
  );
}
