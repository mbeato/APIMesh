import { Database } from "bun:sqlite";
import { sendLowBalanceAlert } from "./email";

export interface CreditTransaction {
  id: string;
  user_id: string;
  type: string;
  amount_microdollars: number;
  description: string | null;
  stripe_payment_intent: string | null;
  api_key_id: string | null;
  api_name: string | null;
  created_at: string;
}

/**
 * Get the current credit balance for a user in microdollars.
 * Returns 0 if no balance row exists.
 */
export function getBalance(db: Database, userId: string): number {
  const row = db.query(
    "SELECT balance_microdollars FROM credit_balances WHERE user_id = ?"
  ).get(userId) as { balance_microdollars: number } | null;
  return row?.balance_microdollars ?? 0;
}

/**
 * Initialize a zero balance for a new user. Called during signup.
 * INSERT OR IGNORE so it's idempotent.
 */
export function initBalance(db: Database, userId: string): void {
  db.run(
    "INSERT OR IGNORE INTO credit_balances (user_id, balance_microdollars) VALUES (?, 0)",
    [userId]
  );
}

/**
 * Add credits to a user's balance (purchase, refund, adjustment).
 * Idempotent on stripe_payment_intent via UNIQUE index.
 */
export function addCredits(
  db: Database,
  userId: string,
  amount: number,
  description: string,
  stripePaymentIntent?: string
): { success: boolean; newBalance: number; error?: string } {
  const txn = db.transaction(() => {
    const id = crypto.randomUUID();

    db.run(
      `INSERT INTO credit_transactions (id, user_id, type, amount_microdollars, description, stripe_payment_intent)
       VALUES (?, ?, 'purchase', ?, ?, ?)`,
      [id, userId, amount, description, stripePaymentIntent ?? null]
    );

    db.run(
      `UPDATE credit_balances SET balance_microdollars = balance_microdollars + ?, updated_at = datetime('now')
       WHERE user_id = ?`,
      [amount, userId]
    );

    const newBalance = getBalance(db, userId);
    return { success: true, newBalance };
  });

  try {
    return txn();
  } catch (err: any) {
    if (err.message?.includes("UNIQUE constraint failed")) {
      return { success: false, newBalance: getBalance(db, userId), error: "duplicate" };
    }
    throw err;
  }
}

/**
 * Check if balance dropped below alert threshold and send email if needed.
 * Fire-and-forget: does not block the caller. 24-hour debounce.
 */
function checkLowBalanceAlert(db: Database, userId: string, newBalance: number): void {
  try {
    const row = db.query(
      `SELECT cb.alert_threshold_microdollars, cb.last_alert_sent_at, u.email
       FROM credit_balances cb
       JOIN users u ON u.id = cb.user_id
       WHERE cb.user_id = ?
       AND cb.alert_threshold_microdollars IS NOT NULL
       AND cb.balance_microdollars <= cb.alert_threshold_microdollars`
    ).get(userId) as { alert_threshold_microdollars: number; last_alert_sent_at: string | null; email: string } | null;

    if (!row) return;

    // 24-hour debounce
    const lastSent = row.last_alert_sent_at ? new Date(row.last_alert_sent_at + "Z").getTime() : 0;
    const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
    if (lastSent > dayAgo) return;

    // Update last_alert_sent_at immediately (before sending) to prevent race conditions
    db.run("UPDATE credit_balances SET last_alert_sent_at = datetime('now') WHERE user_id = ?", [userId]);

    // Fire-and-forget email
    sendLowBalanceAlert(row.email, newBalance, row.alert_threshold_microdollars).catch((err) => {
      console.error("[credits] Failed to send low balance alert:", err);
    });
  } catch (err) {
    // Never let alert check break the deduction flow
    console.error("[credits] Alert check error:", err);
  }
}

/**
 * Atomically deduct credits, record the transaction, and update api_key last_used_at.
 * Uses BEGIN IMMEDIATE to prevent concurrent deductions from causing negative balances.
 * All three operations (balance, ledger, last_used_at) are in one transaction.
 */
export function deductAndRecord(
  db: Database,
  userId: string,
  amount: number,
  description: string,
  apiKeyId: string,
  apiName: string
): { success: boolean; newBalance: number } {
  const txn = db.transaction(() => {
    // Deduct balance — only if sufficient
    const result = db.run(
      `UPDATE credit_balances SET balance_microdollars = balance_microdollars - ?, updated_at = datetime('now')
       WHERE user_id = ? AND balance_microdollars >= ?`,
      [amount, userId, amount]
    );

    if (result.changes === 0) {
      throw new Error("INSUFFICIENT_CREDITS");
    }

    // Record the deduction in the ledger
    const id = crypto.randomUUID();
    db.run(
      `INSERT INTO credit_transactions (id, user_id, type, amount_microdollars, description, api_key_id, api_name)
       VALUES (?, ?, 'usage', ?, ?, ?, ?)`,
      [id, userId, -amount, description, apiKeyId, apiName]
    );

    // Update API key last_used_at atomically with the deduction
    db.run(
      `UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?`,
      [apiKeyId]
    );

    return { success: true, newBalance: getBalance(db, userId) };
  });

  // Use .immediate() for BEGIN IMMEDIATE transaction
  try {
    const result = txn.immediate();
    // Fire-and-forget alert check (only on success)
    if (result.success) {
      checkLowBalanceAlert(db, userId, result.newBalance);
    }
    return result;
  } catch (err: any) {
    if (err.message === "INSUFFICIENT_CREDITS") {
      return { success: false, newBalance: -1 };
    }
    throw err;
  }
}

/**
 * Get transaction history for a user.
 */
export function getTransactions(
  db: Database,
  userId: string,
  limit: number = 50,
  offset: number = 0
): CreditTransaction[] {
  return db.query(
    `SELECT * FROM credit_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(userId, limit, offset) as CreditTransaction[];
}
