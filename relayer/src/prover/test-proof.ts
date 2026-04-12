import { readFile } from "fs/promises";
import { parseEmail } from "../email/parser.js";
import { fetchDKIMPublicKey } from "../email/dkim.js";
import { buildWitness } from "./witness.js";
import { generateProof, verifyProof } from "./prover.js";

const emlPath = process.argv[2];
if (!emlPath)
  throw new Error("Usage: tsx src/prover/test-proof.ts <path-to.eml>");

const rawEml = await readFile(emlPath);
const parsed = await parseEmail(rawEml);
const pubkey = await fetchDKIMPublicKey(
  parsed.dkim.selector,
  parsed.dkim.domain
);
const witness = buildWitness(parsed, pubkey, 1n, 1n);

console.log("Generating proof (this takes a few seconds)...");
const result = await generateProof(witness);
console.log("Proof generated ✓");
console.log("Proof size:", result.proof.length, "bytes");
console.log("Public inputs size:", result.publicInputs.length, "bytes");
console.log("VK size:", result.verificationKey.length, "bytes");

const valid = await verifyProof(result);
console.log("Proof verified:", valid);
