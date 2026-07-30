import { describe, expect, it, vi } from "vitest";
import {
  checkAnonymousSignIns,
  checkEmailConfirmation,
  checkMfa,
  checkPasswordPolicy,
  checkSessionPolicy,
  isUnrecognisedAuthConfig,
  scanAuthPolicy,
} from "./authPolicyScan";

describe("B1 anonymous sign-ins", () => {
  it("flags when enabled", () => {
    const out = checkAnonymousSignIns({ external_anonymous_users_enabled: true });
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
  });

  // A legitimate feature on its own; the graph is what makes it critical.
  it("says it is a real feature rather than implying carelessness", () => {
    const out = checkAnonymousSignIns({ external_anonymous_users_enabled: true });
    expect(out[0].consequence).toContain("that is a real feature".replace("that", "That"));
    expect(out[0].consequence).toContain("what `authenticated` means");
  });

  it("is silent when disabled or unknown", () => {
    expect(checkAnonymousSignIns({ external_anonymous_users_enabled: false })).toEqual([]);
    expect(checkAnonymousSignIns({})).toEqual([]);
  });
});

describe("B2 email confirmation", () => {
  it("flags auto-confirmed sign-ups", () => {
    expect(checkEmailConfirmation({ mailer_autoconfirm: true })).toHaveLength(1);
  });

  // The impersonation angle is the one people miss.
  it("names impersonation, not just spam", () => {
    const out = checkEmailConfirmation({ mailer_autoconfirm: true });
    expect(out[0].consequence).toContain("SOMEONE ELSE'S email");
  });

  it("is silent when confirmation is required", () => {
    expect(checkEmailConfirmation({ mailer_autoconfirm: false })).toEqual([]);
  });
});

describe("B4 password policy", () => {
  it("flags a minimum below 8", () => {
    const out = checkPasswordPolicy({ password_min_length: 6 });
    expect(out[0].id).toBe("auth_policy:weak_password_length");
    expect(out[0].title).toContain("6 characters");
  });

  it("explains that raising it costs existing users nothing", () => {
    expect(checkPasswordPolicy({ password_min_length: 6 })[0].consequence).toContain("existing users keep their passwords");
  });

  it("is silent on a sane minimum with complexity set", () => {
    expect(checkPasswordPolicy({ password_min_length: 10, password_required_characters: "abc" })).toEqual([]);
  });

  // Length matters more than symbols; this must not be alarmist.
  it("treats missing complexity as INFO and says length matters more", () => {
    const out = checkPasswordPolicy({ password_min_length: 10 });
    expect(out[0].severity).toBe("INFO");
    expect(out[0].consequence).toContain("length matters considerably more");
  });

  it("is silent when the setting is unknown", () => {
    expect(checkPasswordPolicy({})).toEqual([]);
  });
});

describe("B5 MFA", () => {
  it("notes when enrolment is disabled", () => {
    const out = checkMfa({ mfa_max_enrolled_factors: 0 });
    expect(out[0].severity).toBe("INFO");
    expect(out[0].consequence).toContain("stolen password is the whole breach");
  });

  it("is silent when available or unknown", () => {
    expect(checkMfa({ mfa_max_enrolled_factors: 2 })).toEqual([]);
    expect(checkMfa({})).toEqual([]);
  });
});

describe("B11 session policy", () => {
  it("flags an access token living longer than a day", () => {
    const out = checkSessionPolicy({ jwt_exp: 604800 });
    expect(out[0].id).toBe("auth_policy:long_session");
    expect(out[0].title).toContain("168 hours");
  });

  // The reason this matters is revocation, not tidiness.
  it("explains that access tokens cannot be revoked", () => {
    expect(checkSessionPolicy({ jwt_exp: 604800 })[0].consequence).toContain("cannot be revoked");
  });

  it("is silent on a normal expiry", () => {
    expect(checkSessionPolicy({ jwt_exp: 3600 })).toEqual([]);
  });

  it("flags refresh tokens that are never rotated", () => {
    const out = checkSessionPolicy({ refresh_token_rotation_enabled: false });
    expect(out[0].id).toBe("auth_policy:no_refresh_rotation");
  });

  it("is silent when rotation is on", () => {
    expect(checkSessionPolicy({ refresh_token_rotation_enabled: true })).toEqual([]);
  });
});

describe("tolerance and safety", () => {
  it("accepts camelCase variants", () => {
    expect(checkAnonymousSignIns({ externalAnonymousUsersEnabled: true })).toHaveLength(1);
    expect(checkSessionPolicy({ jwtExp: 604800 })).toHaveLength(1);
  });

  it("accepts stringified values", () => {
    expect(checkEmailConfirmation({ mailer_autoconfirm: "true" })).toHaveLength(1);
    expect(checkPasswordPolicy({ password_min_length: "6" })).toHaveLength(1);
  });

  // An unrecognised key must never read as a clean project.
  it("detects a config shape it does not understand", () => {
    expect(isUnrecognisedAuthConfig({ some_future_shape: 1 })).toBe(true);
    expect(isUnrecognisedAuthConfig({ jwt_exp: 3600 })).toBe(false);
    expect(isUnrecognisedAuthConfig({})).toBe(false);
  });

  it("logs loudly and reports nothing on an unrecognised shape", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(scanAuthPolicy({ totally_new: "x" })).toEqual([]);
    expect(spy).toHaveBeenCalledWith(expect.stringContaining("did NOT run"), expect.any(String));
    spy.mockRestore();
  });

  it("reports nothing for a null config — a failed fetch is not a pass", () => {
    expect(scanAuthPolicy(null)).toEqual([]);
  });

  it("is silent on a well-configured project", () => {
    expect(
      scanAuthPolicy({
        external_anonymous_users_enabled: false,
        mailer_autoconfirm: false,
        password_min_length: 10,
        password_required_characters: "lower_upper_letters_digits",
        mfa_max_enrolled_factors: 2,
        jwt_exp: 3600,
        refresh_token_rotation_enabled: true,
      })
    ).toEqual([]);
  });

  it("combines every finding for a project left at risky defaults", () => {
    const out = scanAuthPolicy({
      external_anonymous_users_enabled: true,
      mailer_autoconfirm: true,
      password_min_length: 6,
      mfa_max_enrolled_factors: 0,
      jwt_exp: 604800,
      refresh_token_rotation_enabled: false,
    });
    expect(out.length).toBe(6);
    expect(new Set(out.map((x) => x.id)).size).toBe(6);
  });
});
