/**
 * NEAR Wallet — подключение кошелька и взаимодействие с TLS Oracle контрактом
 */

import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupMyNearWallet } from "@near-wallet-selector/my-near-wallet";
import { setupModal } from "@near-wallet-selector/modal-ui";
import "@near-wallet-selector/modal-ui/styles.css";

let selector = null;
let modal = null;
let contractId = "";

// ── Инициализация ─────────────────────────────────────────────

export async function initWalletSelector(networkId = "testnet", contract = "", nodeUrl = "") {
  contractId = contract;

  const network = nodeUrl
    ? { networkId, nodeUrl }
    : networkId;

  selector = await setupWalletSelector({
    network,
    modules: [
      setupMyNearWallet({
        walletUrl:
          networkId === "testnet"
            ? "https://testnet.mynearwallet.com"
            : "https://app.mynearwallet.com",
      }),
    ],
    // Не создаём access key — контракт может не быть задеплоен,
    // а также пользователю не нужен function-call key для API-ключей
  });

  modal = setupModal(selector, {
    theme: "dark",
  });
  return { selector, modal };
}

// ── Аккаунт ───────────────────────────────────────────────────

export function getAccount() {
  if (!selector) return null;
  const state = selector.store.getState();
  const accounts = state.accounts || [];
  return accounts.length > 0 ? accounts[0] : null;
}

export function onAccountChange(callback) {
  if (!selector) return () => {};
  return selector.store.observable.subscribe((state) => {
    const accounts = state.accounts || [];
    callback(accounts.length > 0 ? accounts[0] : null);
  });
}

export function getSelector() {
  return selector;
}

export function showModal() {
  modal?.show();
}

export async function signOut() {
  if (!selector) return;
  const wallet = await selector.wallet();
  await wallet.signOut();
}

// ── Контрактные вызовы ────────────────────────────────────────

/**
 * Отправить аттестацию с ZK proof + подпись нотариуса в контракт
 * Groth16 proof + ecrecover верифицируются on-chain
 */
export async function submitAttestation(attestation) {
  const wallet = await selector.wallet();
  return wallet.signAndSendTransaction({
    receiverId: contractId,
    actions: [
      {
        type: "FunctionCall",
        params: {
          methodName: "submit_attestation",
          args: {
            source_url: attestation.sourceUrl,
            server_name: attestation.serverName,
            timestamp: attestation.timestamp,
            response_data: attestation.responseData,
            proof_a: attestation.proofA,
            proof_b: attestation.proofB,
            proof_c: attestation.proofC,
            public_signals: attestation.publicSignals,
            notary_signature: attestation.notarySignature,
            notary_sig_v: attestation.notarySigV,
          },
          gas: "200000000000000", // 200 TGas (Groth16 + ecrecover)
          deposit: "50000000000000000000000", // 0.05 NEAR (storage)
        },
      },
    ],
  });
}
