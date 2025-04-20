function* LcgGenerator(
  m: bigint,
  a: bigint,
  c: bigint,
  seed: bigint
): Generator<bigint> {
  while (true) {
    seed = (a * seed + c) % m;
    yield seed;
  }
}

export const GetLcg = (lcg: Generator<bigint>): bigint => lcg.next().value;

/*
These values are common parameters for LCG.
They are based on the parameters table provided from wikipedia (MMIX by Donald Knuth):
https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use
*/
const MODULUS = 18_446_744_073_709_551_616n; // m => A prime number (2^16+1)
const MULTIPLIER = 6_364_136_223_846_793_005n; // a => Primitive root modulo

// c => Setting c = 0 makes this a Multiplicative Congruential Generator (MCG)
const INCREMENT = 1_442_695_040_888_963_407n;

const INITIALSEED = BigInt(Date.now()); // Random initial seed within the range [1, m - 1]

export const LCG = LcgGenerator(MODULUS, MULTIPLIER, INCREMENT, INITIALSEED);
