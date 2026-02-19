/**
 * NEAR Wallet — подключение кошелька и взаимодействие с TLS Oracle контрактом
 */

import { setupWalletSelector, actionCreators } from "@near-wallet-selector/core";
import { setupMyNearWallet } from "@near-wallet-selector/my-near-wallet";
import { setupModal } from "@near-wallet-selector/modal-ui";

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
    createAccessKeyFor: contract
      ? {
          contractId: contract,
          methodNames: ["submit_attestation"],
        }
      : undefined,
  });

  modal = setupModal(selector, {
    theme: "dark",
    contractId: contract || undefined,
    methodNames: ["submit_attestation"],
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
 * Отправить аттестацию в контракт (с attached deposit для storage)
 */
export async function submitAttestation(attestation) {
  const wallet = await selector.wallet();
  return wallet.signAndSendTransaction({
    receiverId: contractId,
    actions: [
      actionCreators.functionCall(
        "submit_attestation",
        {
          source_url: attestation.sourceUrl,
          server_name: attestation.serverName,
          timestamp: attestation.timestamp,
          response_data: attestation.responseData,
          notary_pubkey: attestation.notaryPubkey,
          signature: attestation.signature,
        },
        "100000000000000", // 100 TGas
        "50000000000000000000000" // 0.05 NEAR (storage)
      ),
    ],
  });
}
