import { Buffer } from "node:buffer";
import * as crypto from "node:crypto"; // standard node js module,
import { input, toHexString } from "./utils.ts";

function AesEncrypt(text: string, key: Buffer): Buffer<ArrayBuffer> {
  // Create cipher (ECB mode, no IV)
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(true); // Enable PKCS#7 padding

  const encrypted = cipher.update(text, "utf8");
  return Buffer.concat([encrypted, cipher.final()]);
}

function AesDecrypt(key: Buffer, encrypted: Buffer): Buffer<ArrayBuffer> {
  // Create decipher
  const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
  decipher.setAutoPadding(true); // Enable PKCS#7 unpadding

  // Decrypt
  const decrypted = decipher.update(encrypted);
  return Buffer.concat([decrypted, decipher.final()]);
}

// Main AES-ECB encryption and decryption
export async function AesTest() {
  try {
    console.log("# ---- AES-ECB ---- #");

    const key = crypto.randomBytes(16);

    const plaintext = await input("Enter text to cipher (AES-ECB): ");
    console.log(`Plaintext: ${plaintext}`);

    // Encrypt
    const encrypted = AesEncrypt(plaintext, key);
    const ciphertextHex = toHexString(encrypted);
    console.log(`Ciphertext (hex): ${ciphertextHex.toUpperCase()}`);

    // Decrypt
    const decrypted = AesDecrypt(key, encrypted).toString("utf8");
    console.log(`Decrypted: ${decrypted}`);
  } catch (error) {
    console.error(`Error: ${error}`);
  } finally {
    console.log("# ---- AES-ECB ---- #");
  }
}
