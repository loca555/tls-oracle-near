import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import "@near-wallet-selector/modal-ui/styles.css";
import {
  initWalletSelector,
  getAccount,
  getSelector,
  showModal,
  signOut,
  onAccountChange,
  submitAttestation,
} from "./near-wallet.js";

const API = "/api";

// ── API key utils ───────────────────────────────────────────

function getApiKey() {
  return localStorage.getItem("tls-oracle-api-key") || "";
}
function setApiKey(key) {
  localStorage.setItem("tls-oracle-api-key", key);
}

// ── Styles ──────────────────────────────────────────────────

const styles = {
  app: { maxWidth: 900, margin: "0 auto", padding: "20px" },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "16px 0",
    borderBottom: "1px solid #1e2a4a",
    marginBottom: 24,
  },
  logo: { fontSize: 22, fontWeight: 700, color: "#7c6bff" },
  btn: {
    padding: "8px 18px",
    borderRadius: 8,
    border: "none",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: 14,
    background: "#4f46e5",
    color: "#fff",
  },
  btnOutline: {
    padding: "8px 18px",
    borderRadius: 8,
    border: "1px solid #4f46e5",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: 14,
    background: "transparent",
    color: "#a5b4fc",
  },
  btnSmall: {
    padding: "5px 12px",
    borderRadius: 6,
    border: "none",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: 12,
    background: "#065f46",
    color: "#6ee7b7",
  },
  card: {
    background: "#111636",
    borderRadius: 12,
    padding: 20,
    marginBottom: 16,
    border: "1px solid #1e2a4a",
  },
  input: {
    width: "100%",
    padding: "10px 14px",
    borderRadius: 8,
    border: "1px solid #2d3a5c",
    background: "#0d1029",
    color: "#e0e0e0",
    fontSize: 14,
    marginBottom: 12,
  },
  select: {
    width: "100%",
    padding: "10px 14px",
    borderRadius: 8,
    border: "1px solid #2d3a5c",
    background: "#0d1029",
    color: "#e0e0e0",
    fontSize: 14,
    marginBottom: 12,
  },
  tag: {
    display: "inline-block",
    padding: "3px 10px",
    borderRadius: 12,
    fontSize: 11,
    fontWeight: 600,
    marginRight: 8,
  },
  mono: {
    fontFamily: "monospace",
    fontSize: 12,
    color: "#8892b0",
    wordBreak: "break-all",
  },
  grid: { display: "grid", gap: 12 },
  tabs: { display: "flex", gap: 8, marginBottom: 20 },
  tab: (active) => ({
    padding: "8px 20px",
    borderRadius: 8,
    border: "none",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: 14,
    background: active ? "#4f46e5" : "#1e2a4a",
    color: active ? "#fff" : "#8892b0",
  }),
  pre: {
    background: "#0d1029",
    padding: 12,
    borderRadius: 8,
    fontSize: 12,
    overflow: "auto",
    maxHeight: 300,
    color: "#a5b4fc",
  },
  status: (ok) => ({
    display: "inline-block",
    padding: "3px 10px",
    borderRadius: 12,
    fontSize: 11,
    fontWeight: 600,
    marginRight: 8,
    background: ok ? "#064e3b" : "#7f1d1d",
    color: ok ? "#6ee7b7" : "#fca5a5",
  }),
};

// ── Main component ──────────────────────────────────────────

function App() {
  const [account, setAccount] = useState(null);
  const [tab, setTab] = useState("prove");
  const [walletReady, setWalletReady] = useState(false);
  const [apiKey, setApiKeyState] = useState(getApiKey());

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API}/near-config`);
        const { networkId, nodeUrl, contractId } = await res.json();
        await initWalletSelector(networkId, contractId, nodeUrl);
        setAccount(getAccount());
        setWalletReady(true);
        onAccountChange(setAccount);
      } catch (err) {
        console.error("Wallet init error:", err);
        setWalletReady(true);
      }
    })();
  }, []);

  // Register API key via NEAR wallet
  const handleRegisterKey = async () => {
    if (!account) return;
    try {
      // 1. Get challenge
      const chalRes = await fetch(`${API}/auth/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ accountId: account.accountId }),
      });
      const { nonce } = await chalRes.json();

      // 2. Get publicKey from wallet selector
      const selector = getSelector();
      const state = selector.store.getState();
      const acc = state.accounts?.[0];
      const publicKey = acc?.publicKey;

      if (!publicKey) {
        throw new Error(
          "Failed to get publicKey. Please reconnect your wallet.",
        );
      }

      // 3. Verify via backend (checks that key belongs to account)
      const verRes = await fetch(`${API}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          accountId: account.accountId,
          nonce,
          publicKey,
        }),
      });

      if (!verRes.ok) {
        const err = await verRes.json().catch(() => ({}));
        throw new Error(err.error || "Verification failed");
      }

      const { apiKey: newKey } = await verRes.json();
      setApiKey(newKey);
      setApiKeyState(newKey);
    } catch (err) {
      alert("Registration error: " + err.message);
    }
  };

  return (
    <div style={styles.app}>
      <header style={styles.header}>
        <span style={styles.logo}>TLS Oracle</span>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {account ? (
            <>
              <span style={{ color: "#8892b0", fontSize: 13 }}>
                {account.accountId}
              </span>
              {!apiKey && (
                <button style={styles.btnSmall} onClick={handleRegisterKey}>
                  Get API Key
                </button>
              )}
              <button style={styles.btnOutline} onClick={signOut}>
                Sign Out
              </button>
            </>
          ) : (
            <button
              style={styles.btn}
              onClick={showModal}
              disabled={!walletReady}
            >
              Connect Wallet
            </button>
          )}
        </div>
      </header>

      {/* Warning: API key required */}
      {account && !apiKey && (
        <div
          style={{
            ...styles.card,
            borderColor: "#854d0e",
            color: "#fbbf24",
            fontSize: 13,
          }}
        >
          An API key is required to request attestations. Click "Get API Key" above.
        </div>
      )}

      <div style={styles.tabs}>
        <button
          style={styles.tab(tab === "prove")}
          onClick={() => setTab("prove")}
        >
          Prove Data
        </button>
        <button
          style={styles.tab(tab === "feed")}
          onClick={() => setTab("feed")}
        >
          Attestation Feed
        </button>
        <button
          style={styles.tab(tab === "notaries")}
          onClick={() => setTab("notaries")}
        >
          Notaries
        </button>
      </div>

      {tab === "prove" && <ProveTab account={account} apiKey={apiKey} />}
      {tab === "feed" && <FeedTab />}
      {tab === "notaries" && <NotariesTab />}
    </div>
  );
}

// ── Tab: Prove Data ─────────────────────────────────────────

function ProveTab({ account, apiKey }) {
  const [templates, setTemplates] = useState([]);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [txHash, setTxHash] = useState(null);

  useEffect(() => {
    fetch(`${API}/templates`)
      .then((r) => r.json())
      .then(setTemplates)
      .catch(() => {});
  }, []);

  const handleProve = async () => {
    if (!url || !apiKey) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setTxHash(null);

    try {
      const res = await fetch(`${API}/prove`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
        },
        body: JSON.stringify({ url }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Submit via user's wallet (user pays gas)
  const handleSubmit = async () => {
    if (!result || !account) return;
    setSubmitting(true);
    setError(null);

    try {
      const outcome = await submitAttestation(result);
      const hash =
        outcome?.transaction?.hash || outcome?.transaction_outcome?.id;
      setTxHash(hash || "submitted");
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div>
      <div style={styles.card}>
        <h3 style={{ marginBottom: 12, color: "#a5b4fc" }}>
          Request TLS Attestation
        </h3>

        <select
          style={styles.select}
          onChange={(e) => {
            if (e.target.value) setUrl(e.target.value);
          }}
          defaultValue=""
        >
          <option value="">Choose a preset or enter URL...</option>
          {templates.map((t) => (
            <option key={t.id} value={t.url}>
              {t.name}
            </option>
          ))}
        </select>

        <input
          style={styles.input}
          placeholder="https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />

        <button
          style={{
            ...styles.btn,
            width: "100%",
            padding: "12px",
            fontSize: 16,
            opacity: !apiKey ? 0.5 : 1,
          }}
          onClick={handleProve}
          disabled={loading || !url || !apiKey}
        >
          {loading
            ? "MPC-TLS + ZK proof..."
            : !apiKey
              ? "API key required"
              : "Get Attestation"}
        </button>
      </div>

      {error && (
        <div
          style={{ ...styles.card, borderColor: "#7f1d1d", color: "#fca5a5" }}
        >
          {error}
        </div>
      )}

      {result && (
        <div style={styles.card}>
          <h3 style={{ marginBottom: 12, color: "#6ee7b7" }}>
            Attestation Received
          </h3>
          <div style={{ marginBottom: 8 }}>
            <span style={styles.tag}>Domain</span>
            <strong>{result.serverName}</strong>
          </div>
          <div style={{ marginBottom: 8 }}>
            <span style={styles.tag}>Timestamp</span>
            {new Date(result.timestamp * 1000).toLocaleString()}
          </div>
          <div style={{ marginBottom: 8 }}>
            <span style={styles.tag}>Data</span>
          </div>
          <pre style={styles.pre}>
            {JSON.stringify(
              JSON.parse(result.responseData || "{}"),
              null,
              2,
            )}
          </pre>
          {result.publicSignals && (
            <div style={{ marginTop: 8 }}>
              <span style={{ ...styles.tag, background: "#1e3a5f", color: "#93c5fd" }}>
                ZK Proof
              </span>
              <span style={{ color: "#6ee7b7", fontSize: 12, fontWeight: 600 }}>
                Groth16 BN254
              </span>
              <div style={{ ...styles.mono, marginTop: 6, fontSize: 11 }}>
                dataCommitment: {result.publicSignals[0]?.slice(0, 30)}...
              </div>
              <div style={{ ...styles.mono, fontSize: 11 }}>
                serverNameHash: {result.publicSignals[1]?.slice(0, 30)}...
              </div>
            </div>
          )}

          <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
            <button
              style={{ ...styles.btn, flex: 1 }}
              onClick={handleSubmit}
              disabled={submitting || !!txHash || !account}
            >
              {submitting
                ? "Confirm in wallet..."
                : txHash
                  ? "Submitted to NEAR"
                  : !account
                    ? "Connect wallet first"
                    : "Submit to NEAR (0.05 NEAR)"}
            </button>
          </div>

          {txHash && (
            <div style={{ marginTop: 12, color: "#6ee7b7", fontSize: 13 }}>
              TX:{" "}
              <a
                href={`https://testnet.nearblocks.io/txns/${txHash}`}
                target="_blank"
                rel="noreferrer"
                style={{ color: "#a5b4fc" }}
              >
                {txHash}
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Tab: Attestation Feed ───────────────────────────────────

function FeedTab() {
  const [attestations, setAttestations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/attestations?limit=50`)
      .then((r) => r.json())
      .then((data) => {
        setAttestations(data || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return <div style={styles.card}>Loading...</div>;
  if (attestations.length === 0)
    return <div style={styles.card}>No attestations yet</div>;

  return (
    <div style={styles.grid}>
      {attestations.map((a) => (
        <div key={a.id} style={styles.card}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginBottom: 8,
            }}
          >
            <strong>
              #{a.id} — {a.serverName}
            </strong>
            <span style={{ color: "#8892b0", fontSize: 12 }}>
              {new Date(a.timestamp * 1000).toLocaleString()}
            </span>
          </div>
          <div style={{ fontSize: 12, color: "#8892b0", marginBottom: 6 }}>
            {a.sourceUrl}
          </div>
          <pre style={{ ...styles.pre, maxHeight: 120 }}>
            {(() => {
              try {
                return JSON.stringify(JSON.parse(a.responseData), null, 2);
              } catch {
                return a.responseData;
              }
            })()}
          </pre>
          <div style={{ marginTop: 6, fontSize: 11, color: "#4b5563" }}>
            Submitter: {a.submitter} | Block: {a.blockHeight}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Tab: Notaries ───────────────────────────────────────────

function NotariesTab() {
  const [notaries, setNotaries] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    fetch(`${API}/notaries`)
      .then((r) => r.json())
      .then(setNotaries)
      .catch(() => {});
    fetch(`${API}/stats`)
      .then((r) => r.json())
      .then(setStats)
      .catch(() => {});
    fetch(`${API}/health`)
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => {});
  }, []);

  return (
    <div>
      {stats && (
        <div style={{ ...styles.card, display: "flex", gap: 32 }}>
          <div>
            <div style={{ fontSize: 24, fontWeight: 700, color: "#a5b4fc" }}>
              {stats.attestationCount || 0}
            </div>
            <div style={{ fontSize: 12, color: "#8892b0" }}>Attestations</div>
          </div>
          <div>
            <div style={{ fontSize: 24, fontWeight: 700, color: "#a5b4fc" }}>
              {stats.notaryCount || 0}
            </div>
            <div style={{ fontSize: 12, color: "#8892b0" }}>Notaries</div>
          </div>
        </div>
      )}

      {health && (
        <div style={styles.card}>
          <h4 style={{ marginBottom: 8, color: "#8892b0" }}>
            Service Status
          </h4>
          <div style={{ display: "flex", gap: 12 }}>
            <span style={styles.status(health.backend)}>Backend</span>
            <span style={styles.status(health.prover)}>Prover</span>
            <span style={styles.status(health.contract)}>Contract</span>
          </div>
        </div>
      )}

      <h3 style={{ marginBottom: 12, marginTop: 16, color: "#a5b4fc" }}>
        Trusted Notaries
      </h3>
      {notaries.length === 0 ? (
        <div style={styles.card}>No notaries registered</div>
      ) : (
        <div style={styles.grid}>
          {notaries.map((n, i) => (
            <div key={i} style={styles.card}>
              <strong>{n.name}</strong>
              <div style={{ fontSize: 12, color: "#8892b0", marginTop: 4 }}>
                {n.url}
              </div>
              <div style={{ ...styles.mono, marginTop: 6 }}>
                Hash: {n.pubkeyHash?.slice(0, 30)}...
              </div>
              <div style={{ fontSize: 11, color: "#4b5563", marginTop: 4 }}>
                Added by: {n.addedBy} | Block: {n.addedAt}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Mount ───────────────────────────────────────────────────

createRoot(document.getElementById("root")).render(<App />);
