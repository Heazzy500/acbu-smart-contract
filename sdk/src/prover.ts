/**
 * Proof generation using Noir in the browser.
 *
 * Uses @noir-lang/noir_js and @noir-lang/backend_barretenberg
 * to compile and prove the ZK-Comply compliance circuit entirely
 * client-side. Raw credential data never leaves the user's device.
 */

import { Noir } from "@noir-lang/noir_js";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import { compile } from "@noir-lang/noir_wasm";
import type { ProofArtifacts, ComplianceInput } from "./types.js";
import {
  computeCommitment,
  computeNullifier,
  fieldToBytes32,
} from "./poseidon.js";

let noirInstance: Noir | null = null;

/**
 * Load and initialize the Noir circuit.
 * Call once at app startup.
 */
export async function loadCircuit(circuitSource: string): Promise<void> {
  const compiled = compile(circuitSource);
  const backend = new BarretenbergBackend(compiled, {
    threads: navigator.hardwareConcurrency || 4,
  });
  noirInstance = new Noir(compiled, backend);
}

/**
 * Generate a zero-knowledge compliance proof.
 *
 * The raw credential data (kycLevel, countryCode, salt) never
 * leaves the browser — it's fed directly into the Wasm prover.
 * Only the proof and public inputs are returned.
 */
export async function generateProof(
  input: ComplianceInput
): Promise<ProofArtifacts> {
  if (!noirInstance) {
    throw new Error("Circuit not loaded. Call loadCircuit() first.");
  }

  const commitment = await computeCommitment(input.credential);
  const nullifier = await computeNullifier(commitment, input.credential.salt);

  const proofData = await noirInstance.generateFinalProof({
    kyc_level: input.credential.kycLevel,
    country_code: input.credential.countryCode,
    salt: input.credential.salt,
    commitment,
    required_kyc: input.requiredKyc,
    allowed_country: input.allowedCountry,
    nullifier,
  });

  return {
    proof: proofData.proof,
    publicInputs: proofData.publicInputs,
    vk: proofData.vk,
    // Use the named value supplied to the circuit. Parsing the final 32 bytes
    // of serialized public inputs coupled replay protection to field ordering.
    nullifier: fieldToBytes32(nullifier),
  };
}
