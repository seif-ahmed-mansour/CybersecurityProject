import * as crypto from "node:crypto"; // standard node js module,
import * as readline from "node:readline"; // Node.js readline module for terminal input

// Function to convert Buffer to hex string for display
function toHexString(buffer: Buffer): string {
  return buffer.toString("hex");
}

// Create readline interface
function createInterface(): readline.Interface {
  return readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
}

async function input(prompt: string): Promise<string> {
  // Create readline interface
  const rl = createInterface();

  // Get user input using a promise
  const plaintext = await new Promise<string>(resolve => {
    rl.question(prompt, answer => {
      resolve(answer);
    });
  });

  // Close the readline interface
  rl.close();

  return plaintext;
}

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
async function AesTest() {
  try {
    const key = crypto.randomBytes(16);

    const plaintext = await input("Enter text to cipher: ");
    console.log("Plaintext:", plaintext);

    // Encrypt
    const encrypted = AesEncrypt(plaintext, key);
    const ciphertextHex = toHexString(encrypted);
    console.log("Ciphertext (hex):", ciphertextHex);

    // Decrypt
    const decrypted = AesDecrypt(key, encrypted).toString("utf8");
    console.log("Decrypted:", decrypted);
  } catch (error) {
    console.error("Error:", error);
  }
}
// Run the example
AesTest();
