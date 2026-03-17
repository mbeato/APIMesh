---
phase: 03-auth-hardening-sessions
plan: 02
subsystem: auth
tags: [password-reset, forgot-password, change-password, email-verification, session-invalidation, hibp, zxcvbn]

# Dependency graph
requires:
  - phase: 02-signup-login
    provides: auth routes, session management, verification code pattern, email module
  - phase: 03-auth-hardening-sessions/01
    provides: progressive lockout fields (failed_logins, locked_until), deleteUserSessions
provides:
  - POST /auth/forgot-password (anti-enumeration, sends 6-digit code)
  - POST /auth/reset-password (validates code, resets password, clears lockout, auto-login)
  - POST /auth/change-password (session-protected, keeps current session)
  - GET /forgot-password page with two-step UX
affects: [03-auth-hardening-sessions/03, account-settings-ui]

# Tech tracking
tech-stack:
  added: []
  patterns: [two-step password reset UX, anti-enumeration on forgot-password, session invalidation on password change]

key-files:
  created:
    - apis/landing/forgot-password.html
  modified:
    - apis/dashboard/index.ts
    - apis/landing/auth.js

key-decisions:
  - "Anti-enumeration: forgot-password always returns success regardless of email existence"
  - "Password reset clears lockout (failed_logins=0, locked_until=NULL) and invalidates ALL sessions"
  - "Password change keeps current session but invalidates all other sessions"
  - "Two-step forgot-password UX: email entry then code + new password (no auto-submit on code)"

patterns-established:
  - "Password reset code reuses HMAC verification_codes pattern with purpose='password_reset'"
  - "Two-step form UX with hidden/shown divs toggled by JS"

requirements-completed: [AUTH-09, AUTH-10, AUTH-11, FE-03]

# Metrics
duration: 5min
completed: 2026-03-17
---

# Phase 3 Plan 2: Password Reset and Change Summary

**Password reset via email with two-step UX (code + new password), anti-enumeration, lockout clearing, and session-protected change-password route**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-17T17:08:36Z
- **Completed:** 2026-03-17T17:13:16Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Three new backend routes: forgot-password (anti-enumeration), reset-password (full reset with lockout clear + auto-login), change-password (session-protected)
- Forgot-password HTML page with two-step UX: email entry then 6-digit code + new password with strength indicator
- auth.js extended with initForgotPassword() handling both steps, code input widget, and form submission
- Rate limiting on both IP and email for password reset requests

## Task Commits

Each task was committed atomically:

1. **Task 1: Add forgot-password, reset-password, and change-password backend routes** - `c35e4b8` (feat)
2. **Task 2: Create forgot-password.html page and extend auth.js** - `9a39a8e` (feat)

## Files Created/Modified
- `apis/dashboard/index.ts` - Added 3 new auth routes + GET /forgot-password page route + imports for deleteUserSessions and sendPasswordResetCode
- `apis/landing/forgot-password.html` - Two-step password reset page with mesh background, dark theme, code inputs, strength bar
- `apis/landing/auth.js` - Added initForgotPassword() with step-1 email submission, step-2 code + password submission

## Decisions Made
- Anti-enumeration: POST /auth/forgot-password always returns `{ success: true }` regardless of whether email exists or is verified
- Password reset clears lockout counters (failed_logins=0, locked_until=NULL) so users locked out by brute force can recover
- Password reset invalidates ALL sessions then creates a fresh one (auto-login after reset)
- Password change preserves current session but invalidates all OTHER sessions via `deleteUserSessions(db, userId, sessionId)`
- Code input widget on forgot-password page does NOT auto-submit (unlike verify page) because it is part of a larger form with password fields

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Password reset and change flows complete
- Ready for plan 03 (account settings UI) which will add the change-password UI
- All auth hardening routes in place: lockout, session limits, password reset, password change

---
*Phase: 03-auth-hardening-sessions*
*Completed: 2026-03-17*
