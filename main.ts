import * as crypto from "node:crypto"; // standard node js module,
import * as readline from "node:readline"; // Node.js readline module for terminal input

// Function to convert Buffer to hex string for display
function toHexString(buffer: Buffer): string {
  return buffer.toString("hex");
}

// Function to validate key length
function validateKey(key: Buffer): void {
  const validLengths = [16, 24, 32]; // AES-128, AES-192, AES-256
  if (!validLengths.includes(key.length)) {
    throw new Error("Invalid key length. Must be 16, 24, or 32 bytes.");
  }
}

// Create readline interface
function createInterface() {
  return readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
}

// Main AES-ECB encryption and decryption
async function aesEcbTest() {
  try {
    // Define a 128-bit (16-byte) key
    // In production, load this securely (e.g., from process.env)
    const key = Buffer.from("Lorem_ipsum_dolo", "utf8"); // 16 bytes
    validateKey(key);

    // Plaintext to encrypt
    // Create readline interface
    const rl = createInterface();

    // Get user input using a promise
    const plaintext = await new Promise<string>(resolve => {
      rl.question("Enter text to cipher: ", answer => {
        resolve(answer);
      });
    });

    // Close the readline interface
    rl.close();
    console.log("Plaintext:", plaintext);

    // Create cipher (ECB mode, no IV)
    const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
    cipher.setAutoPadding(true); // Enable PKCS#7 padding

    // Encrypt
    let encrypted = cipher.update(plaintext, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const ciphertextHex = toHexString(encrypted);
    console.log("Ciphertext (hex):", ciphertextHex);

    // Create decipher
    const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
    decipher.setAutoPadding(true); // Enable PKCS#7 unpadding

    // Decrypt
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    console.log("Decrypted:", decrypted.toString("utf8"));
  } catch (error) {
    console.error("Error:", error);
  }
}
// Run the example
aesEcbTest();
