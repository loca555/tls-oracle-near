/**
 * Генератор witness-данных для circom circuit AttestationVerifier
 *
 * Принимает attestation и конвертирует в формат circom:
 * - responseData → 17 блоков по 31 байт → BN254 Fr (little-endian decimal strings)
 * - serverName → 8 блоков по 31 байт
 * - notaryPubkey → [x, y] усечённые до 253 бит
 */

import { readFileSync, writeFileSync } from "fs";
import { buildPoseidon } from "circomlibjs";

// BN254 порядок скалярного поля (Fr)
const FR_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Конвертирует bytes в BN254 Fr (31 байт max, little-endian)
 */
function bytesToFr(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = value * 256n + BigInt(bytes[i]);
  }
  return value % FR_ORDER;
}

/**
 * Разбивает строку на блоки по 31 байт → массив Fr
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
 * Конвертирует secp256k1 compressed/uncompressed pubkey в [x_fr, y_fr]
 * Для MVP: берём hex pubkey и усекаем x,y до 253 бит
 */
function pubkeyToFrPair(pubkeyBase64) {
  const bytes = Buffer.from(pubkeyBase64, "base64");

  let x, y;
  if (bytes.length === 33) {
    // Compressed: только x, y вычисляется (для circuit нужен только hash)
    x = bytesToFr(bytes.slice(1, 33));
    y = 0n; // placeholder — в MVP не проверяем подпись в circuit
  } else if (bytes.length === 65) {
    // Uncompressed: 04 || x || y
    x = bytesToFr(bytes.slice(1, 33));
    y = bytesToFr(bytes.slice(33, 65));
  } else if (bytes.length === 32) {
    // Raw 32 bytes (legacy Ed25519 format)
    x = bytesToFr(bytes);
    y = 0n;
  } else {
    throw new Error(`Неизвестный формат pubkey: ${bytes.length} байт`);
  }

  // Усекаем до 253 бит (BN254 Fr)
  const mask253 = (1n << 253n) - 1n;
  return [(x & mask253).toString(), (y & mask253).toString()];
}

/**
 * Генерирует полный input для circom circuit
 */
export async function generateCircuitInput(attestation) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  // Разбиваем данные на chunks
  const responseDataChunks = stringToChunks(
    attestation.responseData,
    17,
  );
  const serverNameChunks = stringToChunks(attestation.serverName, 8);
  const notaryPubkeyPair = pubkeyToFrPair(attestation.notaryPubkey);

  // Вычисляем Poseidon хеши (public signals)
  // Двухуровневый Poseidon для data (17 > 16 max inputs):
  //   hash1 = Poseidon(chunks[0..8]), hash2 = Poseidon(chunks[9..16])
  //   dataCommitment = Poseidon(hash1, hash2)
  const dataChunksBig = responseDataChunks.map(BigInt);
  const dataHash1 = poseidon(dataChunksBig.slice(0, 9));
  const dataHash2 = poseidon(dataChunksBig.slice(9, 17));
  const dataCommitment = F.toString(
    poseidon([dataHash1, dataHash2]),
  );
  const serverNameHash = F.toString(
    poseidon(serverNameChunks.map(BigInt)),
  );
  const notaryPubkeyHash = F.toString(
    poseidon(notaryPubkeyPair.map(BigInt)),
  );

  return {
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
}

// CLI: node input_generator.js [attestation.json] [output.json]
if (process.argv[1]?.endsWith("input_generator.js")) {
  const inputFile = process.argv[2] || "test_attestation.json";
  const outputFile = process.argv[3] || "input.json";

  let attestation;
  if (process.argv[2] === "--test") {
    // Тестовые данные
    attestation = {
      responseData: '{"bitcoin":{"usd":95000}}',
      serverName: "api.coingecko.com",
      timestamp: 1740000000,
      notaryPubkey: Buffer.from(new Uint8Array(32).fill(1)).toString("base64"),
    };
  } else {
    attestation = JSON.parse(readFileSync(inputFile, "utf8"));
  }

  const input = await generateCircuitInput(attestation);
  writeFileSync(outputFile, JSON.stringify(input, null, 2));
  console.log(`Input записан в ${outputFile}`);
  console.log(`Public signals: dataCommitment=${input.dataCommitment}`);
}
