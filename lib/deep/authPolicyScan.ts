import type { GithubFinding } from "./githubScan";
import type { SupabaseAuthConfig } from "./supabaseMgmt";

// B1, B2, B4, B5, B11 — the authentication posture, from the config we already
// fetch for B7. No new connection, no new permission, one extra pass over data
// already in memory.
//
// These are cheap to check and expensive to get wrong, and they share a shape:
// each is a default that was fine while the app had no users and is not fine
// now. Nobody sets out to allow four-character passwords; they leave the
// project at its defaults and ship, which is exactly what this ICP does.
//
// THE GRADING RULE: severity reflects what an attacker gains, not how far the
// setting is from ideal. Anonymous sign-ins are CRITICAL only in combination —
// on their own they are a legitimate feature, and the graph is what turns them
// into "anyone can read every invoice". Reported here at the severity they carry
// alone, and escalated by the reasoner when a path exists.
//
// FIELD NAMES ARE READ TOLERANTLY, for the reason recorded in authConfigScan.ts:
// an unrecognised key looks exactly like a clean project, which is how two
// advisor lints stayed silent for months. Every read accepts the documented
// name plus plausible variants, and a config with none of them logs loudly.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id,
  severity,
  title,
  consequence,
  packageName: null,
  version: null,
  vulnId: null,
  cveId: null,
});

function readBool(config: SupabaseAuthConfig, keys: string[]): boolean | null {
  for (const key of keys) {
    const value = config[key];
    if (typeof value === "boolean") return value;
    if (value === "true") return true;
    if (value === "false") return false;
  }
  return null;
}

function readNumber(config: SupabaseAuthConfig, keys: string[]): number | null {
  for (const key of keys) {
    const value = config[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && /^\d+$/.test(value)) return Number.parseInt(value, 10);
  }
  return null;
}

function readString(config: SupabaseAuthConfig, keys: string[]): string | null {
  for (const key of keys) {
    const value = config[key];
    if (typeof value === "string") return value;
  }
  return null;
}

const ANON_KEYS = ["external_anonymous_users_enabled", "externalAnonymousUsersEnabled", "enable_anonymous_sign_ins"];
const AUTOCONFIRM_KEYS = ["mailer_autoconfirm", "mailerAutoconfirm", "autoconfirm"];
const PW_LENGTH_KEYS = ["password_min_length", "passwordMinLength"];
const PW_CHARS_KEYS = ["password_required_characters", "passwordRequiredCharacters"];
const MFA_KEYS = ["mfa_max_enrolled_factors", "mfaMaxEnrolledFactors"];
const JWT_EXP_KEYS = ["jwt_exp", "jwtExp"];
const REFRESH_ROTATION_KEYS = ["refresh_token_rotation_enabled", "refreshTokenRotationEnabled"];

/** True when none of the keys this module understands are present. */
export function isUnrecognisedAuthConfig(config: SupabaseAuthConfig): boolean {
  if (Object.keys(config).length === 0) return false;
  return (
    readBool(config, ANON_KEYS) === null &&
    readBool(config, AUTOCONFIRM_KEYS) === null &&
    readNumber(config, PW_LENGTH_KEYS) === null &&
    readNumber(config, MFA_KEYS) === null &&
    readNumber(config, JWT_EXP_KEYS) === null
  );
}

/** B1 — anonymous sign-ins. */
export function checkAnonymousSignIns(config: SupabaseAuthConfig): GithubFinding[] {
  if (readBool(config, ANON_KEYS) !== true) return [];
  return [
    f(
      "auth_policy:anonymous_signins",
      "WARNING",
      "Anonymous sign-in is enabled",
      "Anyone can obtain a signed-in session on your project without providing an email or a password. That is a real feature — it is how guest carts and try-before-signup flows work — so this is not automatically wrong. " +
        "It matters because it changes what `authenticated` means in your policies: every rule written as \"logged-in users can read this\" now also means \"anybody at all can read this\". " +
        "If you are not using anonymous sign-ins deliberately, turn them off in Authentication → Providers. If you are, check that no policy grants access on the strength of being authenticated alone."
    ),
  ];
}

/** B2 — email confirmation. */
export function checkEmailConfirmation(config: SupabaseAuthConfig): GithubFinding[] {
  if (readBool(config, AUTOCONFIRM_KEYS) !== true) return [];
  return [
    f(
      "auth_policy:email_not_confirmed",
      "WARNING",
      "New accounts are active without confirming their email",
      "Sign-ups are auto-confirmed, so an account works immediately with an address nobody proved they own. Two consequences worth separating. " +
        "First, anyone can create unlimited accounts with addresses they do not control, which is how free-tier abuse and spam start. " +
        "Second, and more serious: someone can sign up using SOMEONE ELSE'S email address. If any part of your app treats an email as identity — inviting a teammate, matching a customer record, restoring access — that account now impersonates a real person. " +
        "Fix: require email confirmation in Authentication → Providers."
    ),
  ];
}

/** B4 — password policy. */
export function checkPasswordPolicy(config: SupabaseAuthConfig): GithubFinding[] {
  const out: GithubFinding[] = [];
  const minLength = readNumber(config, PW_LENGTH_KEYS);

  if (minLength !== null && minLength < 8) {
    out.push(
      f(
        "auth_policy:weak_password_length",
        "WARNING",
        `Passwords as short as ${minLength} characters are accepted`,
        `Your project accepts passwords of ${minLength} characters. Short passwords are not guessed one at a time — they are cracked offline in bulk if a password database is ever exposed, and the difference between 6 and 8 characters is minutes versus considerably longer. ` +
          `The cost of raising it is close to zero: existing users keep their passwords and are unaffected. Set the minimum to at least 8 in Authentication → Providers, and consider enabling the leaked-password check while you are there.`
      )
    );
  }

  const required = readString(config, PW_CHARS_KEYS);
  if (minLength !== null && minLength >= 8 && (required === null || required === "")) {
    out.push(
      f(
        "auth_policy:no_password_complexity",
        "INFO",
        "No character requirements on passwords",
        "Passwords have a reasonable minimum length but no character-class requirement. This is a note rather than a problem — length matters considerably more than symbol requirements, and forced complexity pushes people toward predictable substitutions. " +
          "Mentioned only so the choice is deliberate. Enabling Supabase's leaked-password check is a better use of the same effort."
      )
    );
  }

  return out;
}

/** B5 — MFA availability. */
export function checkMfa(config: SupabaseAuthConfig): GithubFinding[] {
  const factors = readNumber(config, MFA_KEYS);
  if (factors === null || factors > 0) return [];
  return [
    f(
      "auth_policy:mfa_unavailable",
      "INFO",
      "Your users cannot turn on two-factor authentication",
      "Multi-factor enrolment is disabled, so no user of your app can add a second factor even if they want to. " +
        "For most consumer apps this is a reasonable default. It becomes worth changing as soon as any account can see other people's data — an admin or support role — because for those accounts a stolen password is the whole breach. " +
        "Enable it in Authentication → Providers; users opt in individually, so nothing changes for anyone who ignores it."
    ),
  ];
}

/** B11 — session lifetime and refresh-token handling. */
export function checkSessionPolicy(config: SupabaseAuthConfig): GithubFinding[] {
  const out: GithubFinding[] = [];
  const jwtExp = readNumber(config, JWT_EXP_KEYS);

  // A day-long access token means a stolen one is useful for a day.
  if (jwtExp !== null && jwtExp > 24 * 60 * 60) {
    const hours = Math.round(jwtExp / 3600);
    out.push(
      f(
        "auth_policy:long_session",
        "WARNING",
        `Access tokens stay valid for ${hours} hours`,
        `Your access tokens live for ${hours} hours. Access tokens cannot be revoked — that is what makes them fast — so this is also how long a stolen one keeps working after you have found out about it and reset the account. ` +
          `The usual reason for a long expiry is to stop users being logged out, but refresh tokens already handle that: a short access token is renewed silently in the background, and the user never notices. ` +
          `An hour is the common setting. Change it in Authentication → Sessions.`
      )
    );
  }

  if (readBool(config, REFRESH_ROTATION_KEYS) === false) {
    out.push(
      f(
        "auth_policy:no_refresh_rotation",
        "WARNING",
        "Refresh tokens are not rotated",
        "A refresh token can be used repeatedly without being replaced. With rotation on, each use issues a new token and retires the old one, so a token stolen from a device or a log stops working the moment the real user's client next refreshes — and the reuse is detectable. " +
          "Without it, a leaked refresh token is a long-lived key to the account with nothing to signal the theft. Enable rotation in Authentication → Sessions."
      )
    );
  }

  return out;
}

/** Every auth-posture check, in one call. */
export function scanAuthPolicy(config: SupabaseAuthConfig | null): GithubFinding[] {
  if (!config) return [];

  if (isUnrecognisedAuthConfig(config)) {
    console.error(
      "[authPolicyScan] auth config had none of the expected keys — B1/B2/B4/B5/B11 did NOT run. Keys seen:",
      Object.keys(config).slice(0, 40).join(", ")
    );
    return [];
  }

  return [
    ...checkAnonymousSignIns(config),
    ...checkEmailConfirmation(config),
    ...checkPasswordPolicy(config),
    ...checkMfa(config),
    ...checkSessionPolicy(config),
  ];
}
