"use client";

// Direction D signature: the Receipt. Every claim ShipLock makes flips
// open into the probe it ran — what we asked the app, what the app
// answered, the verdict. The customer will rarely read one. It's there
// so they don't have to.

export interface ReceiptData {
  asked: string;
  answer: string;
  verdict: string;
  ok: boolean;
}

interface ProbeSpec {
  asked: string;
  bad: { answer: string; verdict: string };
  good: { answer: string; verdict: string };
}

const PROBES: Record<number, ProbeSpec> = {
  1: {
    asked: "SELECT * FROM customers LIMIT 50 — signed in as nobody at all",
    bad: {
      answer: "200 OK — 47 rows returned. Full table readable.",
      verdict: "Should have been refused. Needs you.",
    },
    good: {
      answer: "permission denied — row-level security refused the read",
      verdict: "Refused, as it should be.",
    },
  },
  6: {
    asked: "POST /auth/v1/signup with an address we don't control",
    bad: {
      answer: "account active immediately — no confirmation step",
      verdict: "Anyone can sign up as anyone. Needs you.",
    },
    good: {
      answer: "session withheld until the email link is clicked",
      verdict: "Held at the door, as it should be.",
    },
  },
  7: {
    asked: "requested a session with no credentials (anonymous sign-in)",
    bad: {
      answer: "session granted — anonymous sign-ins are enabled",
      verdict: "An open side door. Needs you.",
    },
    good: {
      answer: "refused — anonymous sign-ins are disabled",
      verdict: "Refused, as it should be.",
    },
  },
  11: {
    asked: "GET / — read every security header on the response",
    bad: {
      answer: "no Content-Security-Policy header present",
      verdict: "Browsers get no script rules. Needs you.",
    },
    good: {
      answer: "Content-Security-Policy present, per-request nonce",
      verdict: "Locked down, as it should be.",
    },
  },
};

export function receiptFor(
  checkId: number,
  checkName: string,
  open: boolean
): ReceiptData {
  const spec = PROBES[checkId];
  if (!spec) {
    return {
      asked: `probed ${checkName.toLowerCase()} the way an attacker would`,
      answer: "no weakness observed in the response",
      verdict: "Holding. Re-verified every sweep.",
      ok: true,
    };
  }
  const side = open ? spec.bad : spec.good;
  return { asked: spec.asked, answer: side.answer, verdict: side.verdict, ok: !open };
}

export function Receipt({
  label,
  refNo,
  data,
  stampLeft,
  stampRight,
}: {
  label: string;
  refNo: string;
  data: ReceiptData;
  stampLeft: string;
  stampRight: string;
}) {
  return (
    <div className="dxd-receipt">
      <div className="dxd-receipt-head">
        <span>{label}</span>
        <span>{refNo}</span>
      </div>
      <dl className="dxd-receipt-body">
        <div className="dxd-receipt-row">
          <dt>We asked</dt>
          <dd>{data.asked}</dd>
        </div>
        <div className="dxd-receipt-row">
          <dt>Your app said</dt>
          <dd>{data.answer}</dd>
        </div>
        <div className="dxd-receipt-row">
          <dt>Verdict</dt>
          <dd className={data.ok ? "dxd-verdict-ok" : "dxd-verdict-bad"}>
            {data.verdict}
          </dd>
        </div>
        <div className="dxd-receipt-stamp">
          <span>{stampLeft}</span>
          <span>{stampRight}</span>
        </div>
      </dl>
    </div>
  );
}
