import { Buffer } from "node:buffer";

/**
 * Perform a 32-bit circular left rotation on a number.
 * @param x - The 32-bit value to rotate.
 * @param n - Number of bits to rotate to the left.
 * @returns The result of rotating x left by n bits (unsigned 32-bit).
 */
function rotateLeft(x: number, n: number): number {
  // Shift left by n and shift right (unsigned) by (32 - n), then combine
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * Preprocesses the input message according to the SHA-1 specification:
 * 1. Convert to UTF-8 buffer
 * 2. Append a single '1' bit (0x80), then pad with zeros
 * 3. Append 64-bit big-endian message length
 * @param message - Input string to hash
 * @returns A Buffer whose length is a multiple of 64 bytes, ready for processing
 */
function preprocess(message: string): Buffer {
  // Convert input string to a Buffer (UTF-8 encoding)
  const buffer = Buffer.from(message, "utf8");
  // Calculate message length in bits
  const bitLength = BigInt(buffer.length * 8);

  // Append the 0x80 byte (1000 0000) to mark the '1' bit
  let paddedBuffer = Buffer.concat([buffer, Buffer.from([0x80])]);
  // Calculate how many padding zeros are needed (to reach 56 mod 64)
  const remainder = paddedBuffer.length % 64;
  const k = (56 - remainder + 64) % 64;
  // Append k zero bytes
  const zeroBytes = Buffer.alloc(k, 0);
  paddedBuffer = Buffer.concat([paddedBuffer, zeroBytes]);

  // Allocate 8 bytes for the 64-bit big-endian length
  const lengthBuf = Buffer.alloc(8);
  lengthBuf.writeBigUInt64BE(bitLength);
  // Append length to complete padding
  paddedBuffer = Buffer.concat([paddedBuffer, lengthBuf]);

  return paddedBuffer;
}

/**
 * Computes the SHA-1 hash of the given message.
 * @param message - The input string to hash
 * @returns The SHA-1 digest as a hex string
 */
function sha1(message: string): string {
  // Preprocess message into padded 512-bit (64-byte) chunks
  const paddedBuf: Buffer = preprocess(message);
  // Initialize hash state variables (big-endian constants)
  let H0 = 0x67452301;
  let H1 = 0xefcdab89;
  let H2 = 0x98badcfe;
  let H3 = 0x10325476;
  let H4 = 0xc3d2e1f0;

  // Process each 512-bit chunk
  for (let i = 0; i < paddedBuf.length; i += 64) {
    // Get a 64-byte view of the current chunk
    const chunk: Buffer = paddedBuf.subarray(i, i + 64);
    // Message schedule array of 80 words
    const W: number[] = new Array(80);

    // Break chunk into sixteen 32-bit big-endian words
    for (let t = 0; t < 16; t++) {
      W[t] = chunk.readUInt32BE(t * 4);
    }

    // Extend the sixteen words into eighty via bitwise operations
    for (let t = 16; t < 80; t++) {
      W[t] = rotateLeft(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    // Initialize working variables for this chunk
    let a = H0;
    let b = H1;
    let c = H2;
    let d = H3;
    let e = H4;

    // Main loop: 80 rounds of hashing
    for (let t = 0; t < 80; t++) {
      let f: number, k: number;

      // Round-based function selection and constant
      if (t <= 19) {
        f = (b & c) | (~b & d); // Ch function
        k = 0x5a827999;
      } else if (t <= 39) {
        f = b ^ c ^ d; // Parity
        k = 0x6ed9eba1;
      } else if (t <= 59) {
        f = (b & c) | (b & d) | (c & d); // Maj function
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d; // Parity
        k = 0xca62c1d6;
      }

      // Compute temp = leftrotate(a,5) + f + e + k + W[t]
      const temp = (rotateLeft(a, 5) + f + e + k + W[t]) >>> 0;
      // Update working variables
      e = d;
      d = c;
      c = rotateLeft(b, 30);
      b = a;
      a = temp;
    }

    // Add this chunk's hash to result so far
    H0 = (H0 + a) >>> 0;
    H1 = (H1 + b) >>> 0;
    H2 = (H2 + c) >>> 0;
    H3 = (H3 + d) >>> 0;
    H4 = (H4 + e) >>> 0;
  }

  // Produce final hash value (20 bytes)
  const hashBuf = Buffer.alloc(20);
  hashBuf.writeUInt32BE(H0, 0);
  hashBuf.writeUInt32BE(H1, 4);
  hashBuf.writeUInt32BE(H2, 8);
  hashBuf.writeUInt32BE(H3, 12);
  hashBuf.writeUInt32BE(H4, 16);

  // Return digest as hex string
  return hashBuf.toString("hex");
}

// Example usage
console.log(sha1("hello")); // aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
