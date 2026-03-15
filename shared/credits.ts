import { Database } from "bun:sqlite";

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
    return txn.immediate();
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
