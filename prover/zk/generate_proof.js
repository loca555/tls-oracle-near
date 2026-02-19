/**
 * Генерация Groth16 proof через snarkjs
 *
 * Вызывается из Rust (zk_prover.rs) как subprocess:
 *   node zk/generate_proof.js <attestation_input.json>
 *
 * Выводит в stdout: { proof: { pi_a, pi_b, pi_c }, publicSignals: [...] }
 */

import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

// snarkjs — глобально установлен или локально
let snarkjs;
try {
  snarkjs = await import("snarkjs");
} catch {
  // Fallback: попробовать глобальный путь
  const { execSync } = await import("child_process");
  const globalPath = execSync("npm root -g", { encoding: "utf8" }).trim();
  snarkjs = await import(join(globalPath, "snarkjs", "build", "main.cjs"));
}

// Загружаем circomlibjs для Poseidon хешей
let buildPoseidon;
try {
  const circomlibjs = await import("circomlibjs");
  buildPoseidon = circomlibjs.buildPoseidon;
} catch {
  // Fallback: загрузить из circuits/node_modules
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const circuitsLib = join(
    __dirname,
    "..",
    "..",
    "circuits",
    "node_modules",
    "circomlibjs",
  );
  const circomlibjs = await import(circuitsLib);
  buildPoseidon = circomlibjs.buildPoseidon;
}

// BN254 Fr order
const FR_ORDER =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Bytes → BN254 Fr (little-endian, макс 31 байт)
 */
function bytesToFr(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = value * 256n + BigInt(bytes[i]);
  }
  return value % FR_ORDER;
}

/**
 * Разбивает строку на 31-byte chunks → Fr
 */
function stringToChunks(str, numChunks) {
  const bytes = Buffer.from(str, "utf8");
  const chunks = [];
  for (let i = 0; i < numChunks; i++) {
    const start = i * 31;
    const end = Math.min(start + 31, bytes.length);
    if (start < bytes.length) {
      chunks.push(bytesToFr(bytes.slice(start, end)).toString());
    } else {
      chunks.push("0");
    }
  }
  return chunks;
}

/**
 * secp256k1 pubkey (base64) → [x_fr, y_fr]
 */
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

// ── Main ─────────────────────────────────────────────────────

const inputFile = process.argv[2];
if (!inputFile) {
  process.stderr.write("Usage: node generate_proof.js <attestation.json>\n");
  process.exit(1);
}

const attestation = JSON.parse(readFileSync(inputFile, "utf8"));

// Генерируем circom input
const poseidon = await buildPoseidon();
const F = poseidon.F;

const responseDataChunks = stringToChunks(attestation.responseData, 17);
const serverNameChunks = stringToChunks(attestation.serverName, 8);
const notaryPubkeyPair = pubkeyToFrPair(attestation.notaryPubkey);

// Двухуровневый Poseidon для data (17 blocks > 16 max)
const dataChunksBig = responseDataChunks.map(BigInt);
const dataHash1 = poseidon(dataChunksBig.slice(0, 9));
const dataHash2 = poseidon(dataChunksBig.slice(9, 17));
const dataCommitment = F.toString(poseidon([dataHash1, dataHash2]));
const serverNameHash = F.toString(poseidon(serverNameChunks.map(BigInt)));
const notaryPubkeyHash = F.toString(poseidon(notaryPubkeyPair.map(BigInt)));

const circuitInput = {
  // Public
  dataCommitment,
  serverNameHash,
  timestamp: attestation.timestamp.toString(),
  notaryPubkeyHash,
  // Private
  responseData: responseDataChunks,
  serverName: serverNameChunks,
  notaryPubkey: notaryPubkeyPair,
};

// Определяем пути к circuit файлам
const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(__dirname, "attestation_js", "attestation.wasm");
const zkeyPath = join(__dirname, "attestation_final.zkey");

// Генерируем proof
const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  circuitInput,
  wasmPath,
  zkeyPath,
);

// Выводим результат в stdout
process.stdout.write(JSON.stringify({ proof, publicSignals }));

// Закрываем Poseidon (ffjavascript worker threads)
await buildPoseidon.then?.(() => {}) || undefined;
process.exit(0);
