import { useState, useEffect } from "react";
import { Shield, ShieldCheck, ShieldAlert, ShieldQuestion, Loader2, RefreshCw } from "lucide-react";
import type { Alert } from "../types/alert";

/**
 * Nine-claim Verify panel — the pitch.
 *
 * Nine rows, PASS/FAIL/UNVERIFIABLE, expandable detail per claim.
 * Live demo: swap the ONNX file → claim 5 flips red.
 */

interface ClaimResult {
  id: string;
  name: string;
  status: "PASS" | "FAIL" | "UNVERIFIABLE";
  detail: string;
  claim_number: number;
}

interface VerifyReport {
  alert_id: string;
  claims: ClaimResult[];
  verified_overall: boolean;
  has_failures: boolean;
  anchor_strength: string;
  generated_at: string;
}

const STATUS_CONFIG = {
  PASS: {
    icon: ShieldCheck,
    color: "#00e5a0",
    bg: "rgba(0, 229, 160, 0.08)",
    border: "rgba(0, 229, 160, 0.25)",
    label: "PASS",
  },
  FAIL: {
    icon: ShieldAlert,
    color: "#ff4757",
    bg: "rgba(255, 71, 87, 0.08)",
    border: "rgba(255, 71, 87, 0.25)",
    label: "FAIL",
  },
  UNVERIFIABLE: {
    icon: ShieldQuestion,
    color: "#ffa502",
    bg: "rgba(255, 165, 2, 0.08)",
    border: "rgba(255, 165, 2, 0.2)",
    label: "UNVERIFIABLE",
  },
};

const CLAIM_DESCRIPTIONS: Record<string, string> = {
  evidence_intact: "Evidence fields have not been modified since the receipt was issued",
  features_intact: "Feature vector matches the committed digest in the receipt",
  approved_model: "Model ONNX file is in the signed release registry",
  approved_pipeline: "Extractor and preprocessor code matches attestation",
  prediction_reproducible: "Re-running inference produces the same class and score",
  policy_intact: "Detection thresholds and guards have not changed since issuance",
  alert_included: "Alert's DSSE envelope is Merkle-included in a signed block",
  history_consistent: "Ledger chain is append-only consistent with published checkpoints",
  externally_timestamped: "Checkpoint is anchored to an external timestamping authority",
};

export default function IntegrityVerifyPanel({ alert }: { alert: Alert | null }) {
  const [report, setReport] = useState<VerifyReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastVerifiedId, setLastVerifiedId] = useState<string | null>(null);

  // Reset state and auto-verify when alert changes
  useEffect(() => {
    if (!alert) {
      setReport(null);
      setError(null);
      setExpanded(null);
      setLastVerifiedId(null);
      return;
    }
    if (alert.id !== lastVerifiedId) {
      // New alert selected — clear old results and auto-verify
      setReport(null);
      setError(null);
      setExpanded(null);
      verify(alert.id);
    }
  }, [alert?.id]);

  const verify = async (alertId: string) => {
    setLoading(true);
    setError(null);
    setLastVerifiedId(alertId);
    try {
      const resp = await fetch(`/api/integrity/verify/${alertId}`);
      const data = await resp.json();
      if (data.error) {
        setError(data.error);
        setReport(null);
      } else {
        setReport(data);
      }
    } catch (e: any) {
      setError(e.message ?? "Network error");
    } finally {
      setLoading(false);
    }
  };

  // Empty state
  if (!alert) {
    return (
      <section className="panel-base flex flex-col items-center justify-center gap-3 p-6 h-full text-center">
        <Shield size={28} className="text-[var(--text-dim)]" />
        <p className="text-[13px] font-medium">Proof-Carrying Alert Verification</p>
        <p className="label-mono text-[9.5px] text-[var(--text-dim)]">
          Select an alert to verify its 9 integrity claims
        </p>
      </section>
    );
  }

  const passCount = report?.claims.filter((c) => c.status === "PASS").length ?? 0;
  const failCount = report?.claims.filter((c) => c.status === "FAIL").length ?? 0;
  const unvCount = report?.claims.filter((c) => c.status === "UNVERIFIABLE").length ?? 0;

  return (
    <section className="panel-base flex flex-col min-h-0 h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--bg-border)]">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-[var(--accent)]" />
          <span className="text-[13px] font-semibold">Integrity Verification</span>
          {report && (
            <span
              className="label-mono text-[8px] px-1.5 py-0.5 rounded-full"
              style={{
                background: report.has_failures
                  ? STATUS_CONFIG.FAIL.bg
                  : STATUS_CONFIG.PASS.bg,
                color: report.has_failures
                  ? STATUS_CONFIG.FAIL.color
                  : STATUS_CONFIG.PASS.color,
                border: `1px solid ${
                  report.has_failures
                    ? STATUS_CONFIG.FAIL.border
                    : STATUS_CONFIG.PASS.border
                }`,
              }}
            >
              {report.has_failures ? "VIOLATION" : report.verified_overall ? "VERIFIED" : "PARTIAL"}
            </span>
          )}
        </div>
        <button
          onClick={() => verify(alert.id)}
          disabled={loading}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] font-medium transition-all"
          style={{
            background: "var(--accent)",
            color: "var(--bg-main)",
            opacity: loading ? 0.6 : 1,
          }}
        >
          {loading ? (
            <Loader2 size={12} className="animate-spin" />
          ) : (
            <RefreshCw size={12} />
          )}
          {loading ? "Verifying…" : report ? "Re-verify" : "Verify"}
        </button>
      </div>

      {/* Alert ID bar */}
      <div className="px-4 py-2 border-b border-[var(--bg-border)] bg-[var(--bg-inset)]">
        <div className="label-mono text-[8px]">Alert</div>
        <div className="mono text-[11px] text-[var(--text-muted)] truncate">{alert.id}</div>
      </div>

      {/* Error */}
      {error && (
        <div className="mx-4 mt-3 p-3 rounded text-[11px] text-[#ff4757]"
             style={{ background: "rgba(255,71,87,0.08)", border: "1px solid rgba(255,71,87,0.2)" }}>
          {error}
        </div>
      )}

      {/* Claims list */}
      {report && (
        <div className="flex-1 overflow-y-auto px-3 py-2 space-y-1">
          {/* Summary bar */}
          <div className="flex items-center gap-3 px-2 py-2 mb-1">
            <Chip color={STATUS_CONFIG.PASS.color} count={passCount} label="Pass" />
            <Chip color={STATUS_CONFIG.FAIL.color} count={failCount} label="Fail" />
            <Chip color={STATUS_CONFIG.UNVERIFIABLE.color} count={unvCount} label="Unverifiable" />
            {report.anchor_strength !== "none" && (
              <span
                className="ml-auto label-mono text-[8px] px-1.5 py-0.5 rounded"
                style={{
                  background: "rgba(0,229,160,0.08)",
                  color: "var(--text-muted)",
                  border: "1px solid rgba(0,229,160,0.15)",
                }}
              >
                anchor: {report.anchor_strength}
              </span>
            )}
          </div>

          {/* Claim rows */}
          {report.claims.map((claim) => {
            const cfg = STATUS_CONFIG[claim.status];
            const Icon = cfg.icon;
            const isExpanded = expanded === claim.id;

            return (
              <div
                key={claim.id}
                className="rounded transition-all cursor-pointer"
                style={{
                  background: isExpanded ? cfg.bg : "transparent",
                  border: `1px solid ${isExpanded ? cfg.border : "transparent"}`,
                }}
                onClick={() => setExpanded(isExpanded ? null : claim.id)}
              >
                <div className="flex items-center gap-2.5 px-3 py-2">
                  <span
                    className="flex items-center justify-center w-5 h-5 rounded-full shrink-0"
                    style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
                  >
                    <Icon size={12} style={{ color: cfg.color }} />
                  </span>

                  <span
                    className="mono text-[10px] w-4 text-center shrink-0"
                    style={{ color: "var(--text-dim)" }}
                  >
                    {claim.claim_number}
                  </span>

                  <span className="text-[12px] font-medium flex-1 truncate">
                    {claim.name}
                  </span>

                  <span
                    className="label-mono text-[8px] px-1.5 py-0.5 rounded shrink-0"
                    style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}` }}
                  >
                    {cfg.label}
                  </span>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="px-3 pb-2.5 pt-0">
                    <div className="pl-[30px] space-y-1.5">
                      <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
                        {claim.detail}
                      </p>
                      {CLAIM_DESCRIPTIONS[claim.id] && (
                        <p className="label-mono text-[8.5px] text-[var(--text-dim)]">
                          {CLAIM_DESCRIPTIONS[claim.id]}
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Initial prompt */}
      {!report && !loading && !error && (
        <div className="flex-1 flex flex-col items-center justify-center gap-2 p-6 text-center">
          <Shield size={32} className="text-[var(--text-dim)] opacity-40" />
          <p className="text-[12px] text-[var(--text-dim)]">
            Click <strong>Verify</strong> to run 9 integrity claims
          </p>
          <p className="label-mono text-[8.5px] text-[var(--text-dim)]">
            Evidence · Features · Model · Pipeline · Replay · Policy · Inclusion · History · Timestamp
          </p>
        </div>
      )}
    </section>
  );
}

function Chip({ color, count, label }: { color: string; count: number; label: string }) {
  return (
    <div className="flex items-center gap-1">
      <span
        className="mono text-[13px] font-bold tabular-nums"
        style={{ color }}
      >
        {count}
      </span>
      <span className="label-mono text-[8px] text-[var(--text-dim)]">{label}</span>
    </div>
  );
}
