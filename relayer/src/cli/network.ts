import * as ccc from "@ckb-ccc/ccc";
import systemScripts from "./system-scripts.json" with { type: "json" };
import * as dotenv from "dotenv";
dotenv.config();
export type Network = "devnet" | "testnet" | "mainnet";

const DEVNET_SCRIPTS = {
  [ccc.KnownScript.Secp256k1Blake160]:
    systemScripts.devnet.secp256k1_blake160_sighash_all.script,
  [ccc.KnownScript.Secp256k1Multisig]:
    systemScripts.devnet.secp256k1_blake160_multisig_all.script,
  [ccc.KnownScript.AnyoneCanPay]: systemScripts.devnet.anyone_can_pay.script,
  [ccc.KnownScript.NervosDao]: systemScripts.devnet.dao.script,
};

export function buildCccClient(network: Network): ccc.Client {
  if (network === "mainnet") return new ccc.ClientPublicMainnet();
  if (network === "testnet") return new ccc.ClientPublicTestnet();
  return new ccc.ClientPublicTestnet({
    url: "http://127.0.0.1:28114",
    scripts: DEVNET_SCRIPTS as any,
  });
}

export function readEnvNetwork(): Network {
  const network = process.env.NETWORK;
  if (network === "mainnet" || network === "testnet" || network === "devnet") {
    return network;
  }
  return "devnet";
}
export const cccClient = buildCccClient(readEnvNetwork());
export const cccSigner = new ccc.SignerCkbPrivateKey(cccClient, process.env.PRIVATE_KEY!);
