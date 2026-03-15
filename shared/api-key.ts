import { Database } from "bun:sqlite";

export interface ApiKeyInfo {
  id: string;
  key_prefix: string;
  label: string;
  last_used_at: string | null;
  revoked: number;
  created_at: string;
}

export interface ApiKeyLookupResult {
  id: string;
  user_id: string;
  key_prefix: string;
  label: string;
  last_used_at: string | null;
  created_at: string;
}

/**
 * Generate a new API key: sk_live_ + 64 hex chars (32 bytes).
 * Returns the plaintext, SHA-256 hash, and 10-char prefix.
 */
export function generateApiKey(): { plaintext: string; hash: string; prefix: string } {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const plaintext = `sk_live_${hex}`;

  const hash = hashApiKey(plaintext);
  const prefix = plaintext.slice(0, 10);

  return { plaintext, hash, prefix };
}

/**
 * Hash an API key with SHA-256. Deterministic.
 */
export function hashApiKey(key: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(key);
  return hasher.digest("hex");
}

/**
 * Create and store an API key. Returns the plaintext (shown once), prefix, and id.
 * Never stores plaintext — only the SHA-256 hash.
 * Rejects if user already has >= 5 active (non-revoked) keys.
 */
export function createApiKey(
  db: Database,
  userId: string,
  label: string
): { plaintext: string; prefix: string; id: string } | { error: string } {
  // Check active key count
  const count = db.query(
    "SELECT COUNT(*) as cnt FROM api_keys WHERE user_id = ? AND revoked = 0"
  ).get(userId) as { cnt: number };

  if (count.cnt >= 5) {
    return { error: "Maximum of 5 active API keys allowed" };
  }

  const { plaintext, hash, prefix } = generateApiKey();
  const id = crypto.randomUUID();

  db.run(
    `INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label)
     VALUES (?, ?, ?, ?, ?)`,
    [id, userId, hash, prefix, label]
  );

  return { plaintext, prefix, id };
}

/**
 * Look up an API key by its plaintext value.
 * Hashes the key and queries WHERE revoked = 0 (uses partial index).
 * Returns null for revoked or non-existent keys.
 */
export function lookupByHash(db: Database, plaintextKey: string): ApiKeyLookupResult | null {
  const hash = hashApiKey(plaintextKey);
  return db.query(
    `SELECT id, user_id, key_prefix, label, last_used_at, created_at
     FROM api_keys WHERE key_hash = ? AND revoked = 0`
  ).get(hash) as ApiKeyLookupResult | null;
}

/**
 * Revoke an API key. Only allows revoking keys owned by the specified user.
 * Returns true if a key was actually revoked.
 */
export function revokeApiKey(db: Database, keyId: string, userId: string): boolean {
  const result = db.run(
    "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?",
    [keyId, userId]
  );
  return result.changes > 0;
}

/**
 * Get all API keys for a user (for display).
 * Never returns key_hash — only prefix, label, metadata.
 */
export function getUserKeys(db: Database, userId: string): ApiKeyInfo[] {
  return db.query(
    `SELECT id, key_prefix, label, last_used_at, revoked, created_at
     FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`
  ).all(userId) as ApiKeyInfo[];
}
