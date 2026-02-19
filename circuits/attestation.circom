pragma circom 2.1.0;

include "node_modules/circomlib/circuits/poseidon.circom";

/// Верификация аттестации TLS Oracle
///
/// Доказывает что Prover знает:
/// - response_data с правильным Poseidon-хешем
/// - server_name с правильным Poseidon-хешем
/// - notary pubkey с правильным Poseidon-хешем
///
/// Public inputs: dataCommitment, serverNameHash, timestamp, notaryPubkeyHash
/// Private inputs: responseData[17], serverName[8], notaryPubkey[2]
///
/// MAX_DATA_BLOCKS=17 → 17×31 = 527 байт (достаточно для JSON-ответов API)

template AttestationVerifier(MAX_DATA_BLOCKS) {
    // ── Public inputs ──────────────────────────────────
    signal input dataCommitment;       // Poseidon(responseData)
    signal input serverNameHash;       // Poseidon(serverName)
    signal input timestamp;            // UNIX timestamp (проверяется контрактом)
    signal input notaryPubkeyHash;     // Poseidon(pubkey_x, pubkey_y)

    // ── Private inputs ─────────────────────────────────
    signal input responseData[MAX_DATA_BLOCKS]; // 31-byte chunks → BN254 Fr
    signal input serverName[8];                  // до 248 байт (8×31)
    signal input notaryPubkey[2];                // secp256k1 (x, y) усечённые до Fr

    // ── Верификация хеша данных ────────────────────────
    // Poseidon поддерживает максимум 16 входов.
    // Для 17 блоков используем двухуровневое дерево:
    //   hash1 = Poseidon(9)(blocks[0..8])
    //   hash2 = Poseidon(8)(blocks[9..16])
    //   dataCommitment = Poseidon(2)(hash1, hash2)
    component dataHash1 = Poseidon(9);
    for (var i = 0; i < 9; i++) {
        dataHash1.inputs[i] <== responseData[i];
    }
    component dataHash2 = Poseidon(8);
    for (var i = 0; i < 8; i++) {
        dataHash2.inputs[i] <== responseData[9 + i];
    }
    component dataHashFinal = Poseidon(2);
    dataHashFinal.inputs[0] <== dataHash1.out;
    dataHashFinal.inputs[1] <== dataHash2.out;
    dataCommitment === dataHashFinal.out;

    // ── Верификация хеша server_name ───────────────────
    component snHash = Poseidon(8);
    for (var i = 0; i < 8; i++) {
        snHash.inputs[i] <== serverName[i];
    }
    serverNameHash === snHash.out;

    // ── Верификация хеша notary pubkey ─────────────────
    component npkHash = Poseidon(2);
    npkHash.inputs[0] <== notaryPubkey[0];
    npkHash.inputs[1] <== notaryPubkey[1];
    notaryPubkeyHash === npkHash.out;

    // timestamp проходит напрямую — проверяется контрактом on-chain
    // (circom не может проверять диапазон без дополнительных constraints)
}

component main {public [dataCommitment, serverNameHash, timestamp, notaryPubkeyHash]}
    = AttestationVerifier(17);
