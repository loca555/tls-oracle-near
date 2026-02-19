/**
 * Вычисление Poseidon хэша нотариального ключа
 * для вызова add_notary в TLS Oracle контракте
 *
 * Использование: node scripts/calc-notary-hash.cjs <base64_pubkey>
 */

const path = require("path");

const FR_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function bytesToFr(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = value * 256n + BigInt(bytes[i]);
  }
  return value % FR_ORDER;
}

function pubkeyToFrPair(pubkeyBase64) {
  const bytes = Buffer.from(pubkeyBase64, "base64");
  let x, y;

  if (bytes.length === 33) {
    x = bytesToFr(bytes.slice(1, 33));
    y = 0n;
  } else if (bytes.length === 65) {
    x = bytesToFr(bytes.slice(1, 33));
    y = bytesToFr(bytes.slice(33, 65));
  } else if (bytes.length === 32) {
    x = bytesToFr(bytes);
    y = 0n;
  } else {
    throw new Error(`Неизвестный формат pubkey: ${bytes.length} байт`);
  }

  const mask253 = (1n << 253n) - 1n;
  return [(x & mask253).toString(), (y & mask253).toString()];
}

(async () => {
  const pubkeyBase64 = process.argv[2];
  if (!pubkeyBase64) {
    console.error("Использование: node scripts/calc-notary-hash.cjs <base64_pubkey>");
    process.exit(1);
  }

  // Загружаем circomlibjs (на Windows нужен file:// URL для ESM import)
  const { pathToFileURL } = require("url");
  let circomlibjs;
  try {
    circomlibjs = await import("circomlibjs");
  } catch {
    const circuitsLib = path.join(__dirname, "..", "circuits", "node_modules", "circomlibjs", "build", "main.cjs");
    circomlibjs = await import(pathToFileURL(circuitsLib).href);
  }

  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;

  console.log("Pubkey (base64):", pubkeyBase64);

  const pair = pubkeyToFrPair(pubkeyBase64);
  console.log("Fr pair:", pair);

  const hash = F.toString(poseidon(pair.map(BigInt)));
  console.log("Poseidon hash:", hash);

  process.exit(0);
})();
