import { secp256k1 } from "@noble/curves/secp256k1.js";
import * as ccc from "@ckb-ccc/ccc";

const privKey = secp256k1.utils.randomPrivateKey();
const pubKey = secp256k1.getPublicKey(privKey, true);
console.log("private key:", ccc.hexFrom(privKey));
console.log("public key: ", ccc.hexFrom(pubKey));
