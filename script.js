// Utility functions
const utils = {
  showError: (message, resultDiv) => {
    resultDiv.innerHTML = `<div class="error">${message}</div>`;
  },

  showResult: (input, output, type, resultDiv) => {
    resultDiv.innerHTML = `
      <div class="result-box">
        <h4>Input:</h4>
        <p>${input}</p>
        <h4>Output:</h4>
        <p class="${type}">${output}</p>
      </div>
    `;
  },

  validateInput: (input, key = null) => {
    if (!input) return "Please enter text to process";
    if (key !== null && !key) return "Please enter a key";
    if (key !== null && key.length !== 16 && !key.includes("-----BEGIN")) return "Key must be exactly 16 characters long";
    return null;
  },

  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const binary = bytes.reduce((str, byte) => str + String.fromCharCode(byte), "");
    return window.btoa(binary);
  },

  base64ToArrayBuffer(base64) {
    try {
      const binaryString = window.atob(base64.trim());
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (error) {
      throw new Error("Invalid base64 format");
    }
  },

  pemToArrayBuffer(pem) {
    // Remove PEM header, footer, and whitespace
    const base64 = pem
      .replace(/-----BEGIN [^-]+-----/, "")
      .replace(/-----END [^-]+-----/, "")
      .replace(/[\n\r\s]/g, "");

    return this.base64ToArrayBuffer(base64);
  },
};

// Simplified SHA-1 implementation
class SHA1Handler {
  static async hash(text) {
    // Using Web Crypto API for better security and simplicity
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
}

// RSA implementation using Web Crypto API
class RSAHandler {
  static async generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );

    // Export the keys to PEM format
    const publicKey = await this.exportPublicKey(keyPair.publicKey);
    const privateKey = await this.exportPrivateKey(keyPair.privateKey);

    return { publicKey, privateKey };
  }

  static async exportPublicKey(key) {
    const exported = await crypto.subtle.exportKey("spki", key);
    const exportedAsBase64 = utils.arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
  }

  static async exportPrivateKey(key) {
    const exported = await crypto.subtle.exportKey("pkcs8", key);
    const exportedAsBase64 = utils.arrayBufferToBase64(exported);
    return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
  }

  static async importPublicKey(pemKey) {
    try {
      const binaryDer = utils.pemToArrayBuffer(pemKey);
      return await crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        true,
        ["encrypt"]
      );
    } catch (error) {
      throw new Error("Invalid public key format");
    }
  }

  static async importPrivateKey(pemKey) {
    try {
      const binaryDer = utils.pemToArrayBuffer(pemKey);
      return await crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        true,
        ["decrypt"]
      );
    } catch (error) {
      throw new Error("Invalid private key format");
    }
  }

  static async encrypt(text, publicKeyPem) {
    try {
      const publicKey = await this.importPublicKey(publicKeyPem);
      const encoder = new TextEncoder();
      const data = encoder.encode(text);

      const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, data);

      return utils.arrayBufferToBase64(encrypted);
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  static async decrypt(encryptedBase64, privateKeyPem) {
    try {
      const privateKey = await this.importPrivateKey(privateKeyPem);
      const encryptedData = utils.base64ToArrayBuffer(encryptedBase64);

      const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedData);

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }
}

// Simplified AES implementation using Web Crypto API
class AESHandler {
  static async generateKey(keyString) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(keyString);
    return await crypto.subtle.importKey("raw", keyData, "AES-CBC", false, ["encrypt", "decrypt"]);
  }

  static async encrypt(text, keyString) {
    const key = await this.generateKey(keyString);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, data);

    const encryptedArray = new Uint8Array(encrypted);
    return {
      iv: Array.from(iv)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
      data: Array.from(encryptedArray)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
    };
  }

  static async decrypt(encryptedObj, keyString) {
    const key = await this.generateKey(keyString);
    const iv = new Uint8Array(encryptedObj.iv.match(/.{2}/g).map((byte) => parseInt(byte, 16)));
    const encryptedData = new Uint8Array(encryptedObj.data.match(/.{2}/g).map((byte) => parseInt(byte, 16)));

    const decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, encryptedData);

    return new TextDecoder().decode(decrypted);
  }
}

// Main application class
class CryptographyVisualizer {
  constructor() {
    this.initializeElements();
    this.addEventListeners();
    this.showSelectedAlgorithm();
    this.generateAndDisplayRSAKeys();
  }

  initializeElements() {
    // Get all DOM elements
    this.elements = {
      algorithmSelect: document.getElementById("algorithm"),
      sha1: {
        section: document.getElementById("sha1-section"),
        input: document.getElementById("sha1Input"),
        button: document.getElementById("generateHash"),
      },
      aes: {
        section: document.getElementById("aes-section"),
        input: document.getElementById("aesInput"),
        key: document.getElementById("aesKey"),
        encryptBtn: document.getElementById("encryptAES"),
        decryptBtn: document.getElementById("decryptAES"),
      },
      rsa: {
        section: document.getElementById("rsa-section"),
        input: document.getElementById("rsaInput"),
        publicKeyDisplay: document.getElementById("publicKeyDisplay"),
        privateKeyDisplay: document.getElementById("privateKeyDisplay"),
        generateKeysBtn: document.getElementById("generateNewKeys"),
        encryptBtn: document.getElementById("encryptRSA"),
        decryptBtn: document.getElementById("decryptRSA"),
      },
      result: document.getElementById("result"),
    };
  }

  addEventListeners() {
    // Add event listeners
    this.elements.algorithmSelect.addEventListener("change", () => this.showSelectedAlgorithm());
    this.elements.sha1.button.addEventListener("click", () => this.handleSHA1());
    this.elements.aes.encryptBtn.addEventListener("click", () => this.handleAESEncrypt());
    this.elements.aes.decryptBtn.addEventListener("click", () => this.handleAESDecrypt());
    this.elements.rsa.generateKeysBtn.addEventListener("click", () => this.generateAndDisplayRSAKeys());
    this.elements.rsa.encryptBtn.addEventListener("click", () => this.handleRSAEncrypt());
    this.elements.rsa.decryptBtn.addEventListener("click", () => this.handleRSADecrypt());
  }

  showSelectedAlgorithm() {
    const algorithm = this.elements.algorithmSelect.value;

    // Hide all sections
    this.elements.sha1.section.classList.add("hidden");
    this.elements.aes.section.classList.add("hidden");
    this.elements.rsa.section.classList.add("hidden");

    // Show selected section
    if (algorithm === "sha1") {
      this.elements.sha1.section.classList.remove("hidden");
    } else if (algorithm === "aes") {
      this.elements.aes.section.classList.remove("hidden");
    } else if (algorithm === "rsa") {
      this.elements.rsa.section.classList.remove("hidden");
    }

    this.elements.result.innerHTML = "";
  }

  async generateAndDisplayRSAKeys() {
    try {
      const { publicKey, privateKey } = await RSAHandler.generateKeyPair();
      this.elements.rsa.publicKeyDisplay.textContent = publicKey;
      this.elements.rsa.privateKeyDisplay.textContent = privateKey;
      this.currentKeys = { publicKey, privateKey };
    } catch (error) {
      utils.showError("Error generating RSA keys: " + error.message, this.elements.result);
    }
  }

  async handleSHA1() {
    const text = this.elements.sha1.input.value;
    const error = utils.validateInput(text);

    if (error) {
      utils.showError(error, this.elements.result);
      return;
    }

    try {
      const hash = await SHA1Handler.hash(text);
      utils.showResult(text, hash, "hash", this.elements.result);
    } catch (error) {
      utils.showError(`Error generating hash: ${error.message}`, this.elements.result);
    }
  }

  async handleAESEncrypt() {
    const text = this.elements.aes.input.value;
    const key = this.elements.aes.key.value;
    const error = utils.validateInput(text, key);

    if (error) {
      utils.showError(error, this.elements.result);
      return;
    }

    try {
      const encrypted = await AESHandler.encrypt(text, key);
      this.elements.aes.input.dataset.encrypted = JSON.stringify(encrypted);
      utils.showResult(text, encrypted.data, "encrypted", this.elements.result);
    } catch (error) {
      utils.showError(`Error encrypting: ${error.message}`, this.elements.result);
    }
  }

  async handleAESDecrypt() {
    const encryptedData = this.elements.aes.input.dataset.encrypted;
    const key = this.elements.aes.key.value;

    if (!encryptedData) {
      utils.showError("Please encrypt some text first", this.elements.result);
      return;
    }

    const error = utils.validateInput("dummy", key);
    if (error) {
      utils.showError(error, this.elements.result);
      return;
    }

    try {
      const encrypted = JSON.parse(encryptedData);
      const decrypted = await AESHandler.decrypt(encrypted, key);
      utils.showResult(encrypted.data, decrypted, "decrypted", this.elements.result);
    } catch (error) {
      utils.showError(`Error decrypting: ${error.message}`, this.elements.result);
    }
  }

  async handleRSAEncrypt() {
    const text = this.elements.rsa.input.value;
    if (!text) {
      utils.showError("Please enter text to encrypt", this.elements.result);
      return;
    }

    try {
      const encrypted = await RSAHandler.encrypt(text, this.currentKeys.publicKey);
      this.elements.rsa.input.dataset.encrypted = encrypted;
      utils.showResult(text, encrypted, "encrypted", this.elements.result);
    } catch (error) {
      utils.showError(`Error encrypting: ${error.message}`, this.elements.result);
    }
  }

  async handleRSADecrypt() {
    const encryptedData = this.elements.rsa.input.dataset.encrypted;
    if (!encryptedData) {
      utils.showError("Please encrypt some text first", this.elements.result);
      return;
    }

    try {
      const decrypted = await RSAHandler.decrypt(encryptedData, this.currentKeys.privateKey);
      utils.showResult(encryptedData, decrypted, "decrypted", this.elements.result);
    } catch (error) {
      utils.showError(`Error decrypting: ${error.message}`, this.elements.result);
    }
  }
}

// Initialize the application
window.addEventListener("DOMContentLoaded", () => {
  new CryptographyVisualizer();
});
