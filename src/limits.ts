/**
 * ShieldCortex — storage limits, defined once.
 *
 * These were previously three separate literals — `database/init.ts`,
 * `cli/doctor.ts` and the backup planner — all spelling `100 * 1024 * 1024`.
 * Three copies of a limit is three chances to drift, and drift between "what
 * fills the disk" and "what reports on the disk" is exactly the class of defect
 * that produced #148.
 *
 * ⚠️ THE TWO LIMITS BELOW ARE NOT THE SAME POLICY, despite currently sharing a
 * number. Folding them into one constant would be a bug, not a tidy-up:
 *
 *   - `DIRECTORY_BUDGET_BYTES` bounds EVERYTHING under ~/.shieldcortex — the
 *     live DB plus its WAL, backups, audit logs and so on. It is what `doctor`
 *     reports on and what the backup planner must respect.
 *   - `MAX_DB_FILE_BYTES` bounds the LIVE DATABASE FILE alone, and exceeding it
 *     blocks the database outright.
 *
 * They are named apart here so a future change to one cannot silently move the
 * other.
 *
 * 📌 Known incoherence, deliberately surfaced rather than papered over: with
 * both at 100 MB, a database at 99 MB is "allowed" by the file cap while
 * already exceeding the whole directory budget on its own — before a single
 * byte of WAL, audit log or backup. The two numbers want separating (a smaller
 * file cap, or a larger directory budget), but that is a policy decision with
 * migration consequences for existing hosts, so it is flagged rather than
 * quietly changed here.
 */

/** Total bytes permitted under ~/.shieldcortex (excluding cached models). */
export const DIRECTORY_BUDGET_BYTES = 100 * 1024 * 1024;

/** Bytes permitted for the live database file alone. Exceeding this blocks it. */
export const MAX_DB_FILE_BYTES = 100 * 1024 * 1024;

/** Live database size at which we warn but keep going. */
export const WARN_DB_FILE_BYTES = 50 * 1024 * 1024;
