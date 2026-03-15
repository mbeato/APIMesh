import zxcvbn from "zxcvbn";

/**
 * Normalizes an email address: trims whitespace, lowercases.
 * Exported separately for consistent use in rate limiting and DB lookups.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Validates an email address.
 * Normalizes first, then checks format constraints.
 */
export function validateEmail(email: string): { valid: boolean; error?: string } {
  const normalized = normalizeEmail(email);

  if (!normalized) {
    return { valid: false, error: "Email is required" };
  }

  if (normalized.length > 254) {
    return { valid: false, error: "Email too long (max 254 characters)" };
  }

  // Basic email regex: user@domain.tld, no spaces
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalized)) {
    return { valid: false, error: "Invalid email format" };
  }

  return { valid: true };
}

/**
 * Validates password strength.
 * Requires length >= 12, <= 128, and zxcvbn score >= 3.
 */
export function validatePassword(password: string): { valid: boolean; score?: number; error?: string } {
  if (password.length < 12) {
    return { valid: false, error: "Password must be at least 12 characters" };
  }

  if (password.length > 128) {
    return { valid: false, error: "Password must be at most 128 characters" };
  }

  const result = zxcvbn(password);

  if (result.score < 3) {
    return { valid: false, score: result.score, error: "Password is too weak" };
  }

  return { valid: true, score: result.score };
}
