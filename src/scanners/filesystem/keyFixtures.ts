// Test helper: throwaway private keys generated at test time so none are committed to the repository.
import { generateKeyPairSync } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";

export const KEY_FIXTURES = ["ed25519-private.pem", "rsa3072-encrypted.pem"] as const;

export async function writeKeyFixtures(dir: string): Promise<Record<(typeof KEY_FIXTURES)[number], string>> {
  const ed = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const rsa = generateKeyPairSync("rsa", { modulusLength: 3072 }).privateKey
    .export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "fixture" }).toString();
  await writeFile(path.join(dir, KEY_FIXTURES[0]), ed);
  await writeFile(path.join(dir, KEY_FIXTURES[1]), rsa);
  return { "ed25519-private.pem": ed, "rsa3072-encrypted.pem": rsa };
}
