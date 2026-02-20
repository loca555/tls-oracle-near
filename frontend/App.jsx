import { Buffer } from "buffer";
globalThis.Buffer = globalThis.Buffer || Buffer;

import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
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
  if (key) {
    localStorage.setItem("tls-oracle-api-key", key);
  } else {
    localStorage.removeItem("tls-oracle-api-key");
  }
}

/** Проверить валидность API-ключа на бэкенде */
async function validateStoredApiKey() {
  const key = getApiKey();
  if (!key) return "";
  try {
    const res = await fetch(`${API}/auth/check`, {
      headers: { "X-API-Key": key },
    });
    if (res.ok) return key;
    // 401 = ключ невалиден — очистить
    localStorage.removeItem("tls-oracle-api-key");
    return "";
  } catch {
    return key; // Сеть недоступна — оставляем ключ
  }
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
  btnDanger: {
    padding: "5px 12px",
    borderRadius: 6,
    border: "none",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: 12,
    background: "#7f1d1d",
    color: "#fca5a5",
  },
  btnWarn: {
    padding: "5px 12px",
    borderRadius: 6,
    border: "none",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: 12,
    background: "#78350f",
    color: "#fbbf24",
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

// NearBlocks URL для testnet
const NEARBLOCKS = "https://testnet.nearblocks.io";

function App() {
  const [account, setAccount] = useState(null);
  const [walletReady, setWalletReady] = useState(false);
  const [apiKey, setApiKeyState] = useState(getApiKey());

  // Проверяем redirect из MyNearWallet
  const hasTxHash = !!window.__NEAR_TX_HASH;
  const [txHash] = useState(window.__NEAR_TX_HASH || null);
  const [txError] = useState(window.__NEAR_TX_ERROR || null);
  const [showTxBanner, setShowTxBanner] = useState(hasTxHash || !!window.__NEAR_TX_ERROR);
  const [tab, setTab] = useState(hasTxHash ? "feed" : "prove");

  // Очищаем глобальные переменные
  if (window.__NEAR_TX_HASH) delete window.__NEAR_TX_HASH;
  if (window.__NEAR_TX_ERROR) delete window.__NEAR_TX_ERROR;

  useEffect(() => {
    (async () => {
      try {
        // Проверяем валидность сохранённого API-ключа (БД могла сброситься при деплое)
        const validKey = await validateStoredApiKey();
        if (validKey !== apiKey) setApiKeyState(validKey);

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

      // 2. Get publicKey — try wallet selector first, fallback to NEAR RPC
      let publicKey = null;
      const selector = getSelector();
      const state = selector.store.getState();
      const acc = state.accounts?.[0];
      publicKey = acc?.publicKey || null;

      if (!publicKey) {
        // Fallback: query NEAR RPC for access keys
        const cfgRes = await fetch(`${API}/near-config`);
        const { nodeUrl } = await cfgRes.json();
        const rpcRes = await fetch(nodeUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0", id: "1", method: "query",
            params: { request_type: "view_access_key_list", finality: "final", account_id: account.accountId },
          }),
        });
        const rpcData = await rpcRes.json();
        const keys = rpcData.result?.keys || [];
        // Prefer full-access key, fallback to any key
        const fullKey = keys.find((k) => k.access_key?.permission === "FullAccess");
        publicKey = fullKey?.public_key || keys[0]?.public_key || null;
      }

      if (!publicKey) {
        throw new Error("No access keys found for this account.");
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

  // Очистить невалидный ключ из state и localStorage
  const clearKey = () => {
    setApiKey("");
    setApiKeyState("");
  };

  // Удалить (деактивировать) API-ключ
  const handleDeleteKey = async () => {
    if (!apiKey) return;
    if (!confirm("Are you sure? The API key will be deactivated.")) return;

    try {
      const res = await fetch(`${API}/auth/key`, {
        method: "DELETE",
        headers: { "X-API-Key": apiKey },
      });

      // Ключ невалиден — просто очищаем
      if (res.status === 401 || res.status === 403) {
        clearKey();
        return;
      }

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${res.status}`);
      }

      clearKey();
    } catch (err) {
      alert("Delete error: " + err.message);
    }
  };

  // Перегенерировать API-ключ (старый деактивируется, выдаётся новый)
  const handleRegenerateKey = async () => {
    if (!apiKey) return;
    if (!confirm("Old key will be deactivated. Generate new one?")) return;

    try {
      const res = await fetch(`${API}/auth/regenerate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
        },
      });

      // Ключ невалиден — очищаем, пользователь получит новый через "Get API Key"
      if (res.status === 401 || res.status === 403) {
        clearKey();
        return;
      }

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${res.status}`);
      }

      const { apiKey: newKey } = await res.json();
      setApiKey(newKey);
      setApiKeyState(newKey);
    } catch (err) {
      alert("Regenerate error: " + err.message);
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
              {!apiKey ? (
                <button style={styles.btnSmall} onClick={handleRegisterKey}>
                  Get API Key
                </button>
              ) : (
                <>
                  <button
                    style={{ ...styles.btnSmall, background: "#1e3a5f", color: "#93c5fd" }}
                    onClick={() => { navigator.clipboard.writeText(apiKey); }}
                    title={apiKey}
                  >
                    Copy API Key
                  </button>
                  <button style={styles.btnWarn} onClick={handleRegenerateKey}>
                    Regenerate
                  </button>
                  <button style={styles.btnDanger} onClick={handleDeleteKey}>
                    Delete Key
                  </button>
                </>
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

      {/* Show API key for copying */}
      {account && apiKey && (
        <div
          style={{
            ...styles.card,
            borderColor: "#1e3a5f",
            fontSize: 13,
          }}
        >
          <div style={{ marginBottom: 6, color: "#93c5fd", fontWeight: 600 }}>Your API Key</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <code style={{ ...styles.mono, flex: 1, fontSize: 13, color: "#a5b4fc" }}>{apiKey}</code>
            <button
              style={{ ...styles.btnSmall, background: "#1e3a5f", color: "#93c5fd", whiteSpace: "nowrap" }}
              onClick={() => navigator.clipboard.writeText(apiKey)}
            >
              Copy
            </button>
            <button
              style={{ ...styles.btnWarn, whiteSpace: "nowrap" }}
              onClick={handleRegenerateKey}
            >
              Regenerate
            </button>
            <button
              style={{ ...styles.btnDanger, whiteSpace: "nowrap" }}
              onClick={handleDeleteKey}
            >
              Delete
            </button>
          </div>
          <div style={{ marginTop: 8, color: "#4b5563", fontSize: 11 }}>
            Use this key in the X-API-Key header for API requests. See docs for integration guide.
          </div>
        </div>
      )}

      {/* Баннер после redirect из MyNearWallet */}
      {showTxBanner && txHash && (
        <div
          style={{
            ...styles.card,
            borderColor: "#065f46",
            background: "#052e16",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div>
            <span style={{ color: "#6ee7b7", fontWeight: 600 }}>
              Attestation submitted to NEAR!
            </span>
            <div style={{ marginTop: 6 }}>
              <a
                href={`${NEARBLOCKS}/txns/${txHash}`}
                target="_blank"
                rel="noreferrer"
                style={{ color: "#a5b4fc", fontSize: 13 }}
              >
                View transaction on NearBlocks
              </a>
              <span style={{ ...styles.mono, marginLeft: 8 }}>
                {txHash.slice(0, 12)}...{txHash.slice(-8)}
              </span>
            </div>
          </div>
          <button
            style={{ ...styles.btnSmall, background: "#1e3a5f", color: "#93c5fd" }}
            onClick={() => setShowTxBanner(false)}
          >
            Dismiss
          </button>
        </div>
      )}
      {showTxBanner && txError && (
        <div
          style={{
            ...styles.card,
            borderColor: "#7f1d1d",
            color: "#fca5a5",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span>Transaction error: {txError}</span>
          <button
            style={{ ...styles.btnDanger }}
            onClick={() => setShowTxBanner(false)}
          >
            Dismiss
          </button>
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

// ESPN лиги
const ESPN_LEAGUES = [
  { sport: "soccer", league: "eng.1", label: "Premier League" },
  { sport: "soccer", league: "esp.1", label: "La Liga" },
  { sport: "soccer", league: "ger.1", label: "Bundesliga" },
  { sport: "soccer", league: "ita.1", label: "Serie A" },
  { sport: "soccer", league: "fra.1", label: "Ligue 1" },
  { sport: "soccer", league: "usa.1", label: "MLS" },
  { sport: "soccer", league: "uefa.champions", label: "Champions League" },
  { sport: "basketball", league: "nba", label: "NBA" },
  { sport: "football", league: "nfl", label: "NFL" },
  { sport: "hockey", league: "nhl", label: "NHL" },
  { sport: "baseball", league: "mlb", label: "MLB" },
];

function ProveTab({ account, apiKey }) {
  const [templates, setTemplates] = useState([]);
  const [mode, setMode] = useState("url"); // "url" | "espn"
  const [url, setUrl] = useState("");
  // ESPN форма
  const [espnLeague, setEspnLeague] = useState("soccer/eng.1");
  const [espnEventId, setEspnEventId] = useState("");
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
    if (!apiKey) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setTxHash(null);

    try {
      let res;
      if (mode === "espn") {
        // ESPN endpoint — компактный JSON + ZK proof
        if (!espnEventId) throw new Error("Event ID обязателен");
        const [sport, league] = espnLeague.split("/");
        res = await fetch(`${API}/prove-espn`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": apiKey,
          },
          body: JSON.stringify({ espnEventId, sport, league }),
        });
      } else {
        // Generic URL
        if (!url) throw new Error("URL обязателен");
        res = await fetch(`${API}/prove`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": apiKey,
          },
          body: JSON.stringify({ url }),
        });
      }
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        if (res.status === 401 || res.status === 403) {
          setApiKey("");
          setApiKeyState("");
        }
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

  const canSubmit = mode === "espn" ? !!espnEventId : !!url;

  return (
    <div>
      <div style={styles.card}>
        <h3 style={{ marginBottom: 12, color: "#a5b4fc" }}>
          Request TLS Attestation
        </h3>

        {/* Переключатель режима */}
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <button
            style={styles.tab(mode === "url")}
            onClick={() => setMode("url")}
          >
            Custom URL
          </button>
          <button
            style={styles.tab(mode === "espn")}
            onClick={() => setMode("espn")}
          >
            ESPN Scores
          </button>
        </div>

        {mode === "url" ? (
          <>
            <select
              style={styles.select}
              onChange={(e) => {
                if (e.target.value) setUrl(e.target.value);
              }}
              defaultValue=""
            >
              <option value="">Choose a preset or enter URL...</option>
              {templates.filter((t) => t.id !== "espn-scores").map((t) => (
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
          </>
        ) : (
          <>
            <select
              style={styles.select}
              value={espnLeague}
              onChange={(e) => setEspnLeague(e.target.value)}
            >
              {ESPN_LEAGUES.map((l) => (
                <option key={`${l.sport}/${l.league}`} value={`${l.sport}/${l.league}`}>
                  {l.label}
                </option>
              ))}
            </select>

            <input
              style={styles.input}
              placeholder="ESPN Event ID (например 740901)"
              value={espnEventId}
              onChange={(e) => setEspnEventId(e.target.value)}
            />

            <div style={{ fontSize: 11, color: "#4b5563", marginBottom: 12 }}>
              MPC-TLS к ESPN API + извлечение компактного счёта + Groth16 ZK proof
            </div>
          </>
        )}

        <button
          style={{
            ...styles.btn,
            width: "100%",
            padding: "12px",
            fontSize: 16,
            opacity: !apiKey ? 0.5 : 1,
          }}
          onClick={handleProve}
          disabled={loading || !canSubmit || !apiKey}
        >
          {loading
            ? "MPC-TLS + ZK proof..."
            : !apiKey
              ? "API key required"
              : mode === "espn"
                ? "Get ESPN Attestation"
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
          <div style={{ marginTop: 8, display: "flex", gap: 16, flexWrap: "wrap", fontSize: 12 }}>
            <span>
              Submitter:{" "}
              <a
                href={`${NEARBLOCKS}/address/${a.submitter}`}
                target="_blank"
                rel="noreferrer"
                style={{ color: "#a5b4fc" }}
              >
                {a.submitter}
              </a>
            </span>
            <span>
              Block:{" "}
              <a
                href={`${NEARBLOCKS}/blocks/${a.blockHeight}`}
                target="_blank"
                rel="noreferrer"
                style={{ color: "#a5b4fc" }}
              >
                #{a.blockHeight}
              </a>
            </span>
          </div>
          <div style={{ marginTop: 6 }}>
            <span
              style={{
                ...styles.tag,
                background: "#1e3a5f",
                color: "#93c5fd",
                fontSize: 10,
              }}
            >
              ZK Verified
            </span>
            {a.sigVerified && (
              <span
                style={{
                  ...styles.tag,
                  background: "#1e3a2f",
                  color: "#86efac",
                  fontSize: 10,
                  marginLeft: 4,
                }}
              >
                Notary Signed
              </span>
            )}
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
