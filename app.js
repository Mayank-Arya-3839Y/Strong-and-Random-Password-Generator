// ============================================================================
// OPTIMIZED PASSWORD SUITE (100% FUNCTIONAL OFFLINE / FILE:// & WEB CRYPTO)
// Fixes applied:
// 1. Fixed POOL_RAW.symbols string escaping (constructed via char codes 33..126)
// 2. Added Pure-JS AES-256-GCM + SHA-256 + 1,000,000 PBKDF2 fallback when
//    opened via file:// (where window.crypto.subtle is locked by browsers)
// 3. Added textarea execCommand('copy') fallback for file:// clipboard access
// 4. Exact binary compatibility with Python Hardened_Password_Vault.py:
//    Base64URL([16B Salt][12B Nonce][16B Tag][Ciphertext])
// ============================================================================

const PBKDF2_ITERATIONS = 1_000_000;
const AMBIGUOUS_CHARS = new Set(["0", "O", "1", "l", "I", "|"]);

// Build printable ASCII symbols cleanly without quote-escaping issues
const ALL_SYMBOLS = Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i))
  .filter(c => !/[a-zA-Z0-9]/.test(c))
  .join("");

const POOL_RAW = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: ALL_SYMBOLS
};

const POOL_FILTERED = {
  lower: [...POOL_RAW.lower].filter(c => !AMBIGUOUS_CHARS.has(c)).join(""),
  upper: [...POOL_RAW.upper].filter(c => !AMBIGUOUS_CHARS.has(c)).join(""),
  digits: [...POOL_RAW.digits].filter(c => !AMBIGUOUS_CHARS.has(c)).join(""),
  symbols: [...POOL_RAW.symbols].filter(c => !AMBIGUOUS_CHARS.has(c)).join("")
};

const LOWER_SET = new Set(POOL_RAW.lower);
const UPPER_SET = new Set(POOL_RAW.upper);
const DIGIT_SET = new Set(POOL_RAW.digits);
const SYMBOL_SET = new Set(POOL_RAW.symbols);
const STANDARD_ALL_SET = new Set([
  ...POOL_RAW.lower,
  ...POOL_RAW.upper,
  ...POOL_RAW.digits,
  ...POOL_RAW.symbols
]);

const WORD_LIST = [
  "acoustic", "alpine", "amber", "anchor", "apollo", "arctic", "arrow", "aspen",
  "atlas", "aurora", "autumn", "avalon", "badger", "bamboo", "banyan", "baron",
  "basalt", "beacon", "bison", "blizzard", "blossom", "boulder", "breeze", "bronze",
  "canyon", "carbon", "cascade", "castle", "cedar", "celeste", "chisel", "chrome",
  "cipher", "citadel", "circuit", "cobalt", "comet", "compass", "condor", "copper",
  "coral", "cosmos", "cougar", "crater", "crimson", "crystal", "cyclone", "cypress",
  "dagger", "delta", "desert", "diamond", "dolphin", "dragon", "dynamo", "eclipse",
  "emerald", "ember", "empire", "enigma", "equinox", "everest", "falcon", "fathom",
  "fjord", "flannel", "flint", "forest", "fortress", "fossil", "fusion", "galaxy",
  "garnet", "gazelle", "geyser", "glacier", "granite", "gravity", "griffin", "harbor",
  "harvest", "helios", "horizon", "hunter", "iceberg", "ignite", "indigo", "infinity",
  "iron", "island", "ivory", "iguana", "jacket", "jaguar", "jasper", "javelin",
  "jester", "jungle", "jupiter", "karma", "kestrel", "kingdom", "krypton", "lagoon",
  "lantern", "lariat", "lava", "legacy", "legend", "leopard", "liberty", "lightning",
  "lithium", "lotus", "lunar", "magnet", "mammoth", "mantis", "marble", "mariner",
  "matrix", "meadow", "mercury", "meteor", "mirage", "monarch", "monsoon", "mosaic",
  "mustang", "nebula", "nectar", "neptune", "nickel", "nimbus", "nitrogen", "nomad",
  "nova", "obsidian", "ocean", "odyssey", "olympus", "omega", "onyx", "opal",
  "orbit", "orchid", "orion", "osprey", "outpost", "oxygen", "pacific", "paladin",
  "panther", "paradox", "pegasus", "pelican", "pendulum", "phantom", "phoenix", "pioneer",
  "planet", "plasma", "platinum", "polaris", "prairie", "prism", "pulsar", "pyramid",
  "python", "quantum", "quartz", "quasar", "quiver", "radon", "raptor", "redwood",
  "sapphire", "saturn", "savanna", "scarlet", "scepter", "scorpion", "sequoia", "serpent",
  "shadow", "sierra", "silver", "solstice", "sonnet", "sparrow", "spectrum", "sphinx",
  "starlight", "stratos", "summit", "tempest", "thunder", "titanium", "topaz", "tornado",
  "trident", "tundra", "typhoon", "umbra", "utopia", "valkyrie", "velvet", "venture",
  "vertex", "viper", "vortex", "voyager", "vulcan", "warden", "whisper", "wildfire",
  "zenith", "zephyr", "zircon", "zodiac"
];

// ============================================================================
// STATE & SESSION KEY CACHE (Zeroed on Wipe)
// ============================================================================
const keyCache = new Map(); // cacheKeyString -> Uint8Array(32)
let keyCacheGeneration = 0;
let screenWipeTimerId = null;
let entropyDebounceId = null;
let isEncrypting = false;
let isDecrypting = false;
const operationIds = { encrypt: 0, decrypt: 0 };

// ============================================================================
// CRYPTOGRAPHICALLY SECURE RANDOM HELPERS
// ============================================================================
function getRandomBytes(n) {
  const buf = new Uint8Array(n);
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < n; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return buf;
}

function secureRandomInt(maxExclusive) {
  const array = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  let val;
  do {
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(array);
      val = array[0];
    } else {
      val = Math.floor(Math.random() * 0x100000000);
    }
  } while (val >= limit);
  return val % maxExclusive;
}

function secureChoice(seq) {
  return seq[secureRandomInt(seq.length)];
}

function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function secureSample(seq, k) {
  const copy = [...seq];
  for (let i = 0; i < k; i++) {
    const j = i + secureRandomInt(copy.length - i);
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy.slice(0, k);
}

function zeroizeBuffer(buf) {
  if (buf instanceof Uint8Array) {
    buf.fill(0);
  }
}

// ============================================================================
// BASE64 & BASE64URL HELPERS (Matches Python base64.urlsafe_b64encode)
// ============================================================================
function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToBytes(b64url) {
  const b64 = b64url.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (b64.length % 4)) % 4;
  const padded = b64 + "=".repeat(padLen);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function utf8ToBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUtf8(b64) {
  const clean = b64.trim();
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) {
    throw new Error("Invalid Base64 string");
  }
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

// ============================================================================
// PURE-JS FALLBACK ENGINE (SHA-256, PBKDF2-HMAC-SHA256, AES-256-GCM)
// Used automatically if index.html is opened over file:// where crypto.subtle
// is disabled by browser security policy.
// ============================================================================
const K_SHA256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function sha256Compress(state, blockWords) {
  const W = sha256Compress.W || (sha256Compress.W = new Uint32Array(64));
  for (let i = 0; i < 16; i++) W[i] = blockWords[i];
  for (let i = 16; i < 64; i++) {
    const v1 = W[i - 15];
    const s0 = ((v1 >>> 7) | (v1 << 25)) ^ ((v1 >>> 18) | (v1 << 14)) ^ (v1 >>> 3);
    const v2 = W[i - 2];
    const s1 = ((v2 >>> 17) | (v2 << 15)) ^ ((v2 >>> 19) | (v2 << 13)) ^ (v2 >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = state[0], b = state[1], c = state[2], d = state[3];
  let e = state[4], f = state[5], g = state[6], h = state[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + S1 + ch + K_SHA256[i] + W[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) | 0;
    h = g; g = f; f = e; e = (d + temp1) | 0;
    d = c; c = b; b = a; a = (temp1 + temp2) | 0;
  }
  state[0] = (state[0] + a) | 0; state[1] = (state[1] + b) | 0;
  state[2] = (state[2] + c) | 0; state[3] = (state[3] + d) | 0;
  state[4] = (state[4] + e) | 0; state[5] = (state[5] + f) | 0;
  state[6] = (state[6] + g) | 0; state[7] = (state[7] + h) | 0;
}

function sha256Bytes(msgBytes) {
  const state = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  const bitLen = msgBytes.length * 8;
  const padLen = ((msgBytes.length + 9 + 63) & ~63);
  const padded = new Uint8Array(padLen);
  padded.set(msgBytes);
  padded[msgBytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padLen - 4, bitLen >>> 0, false);
  view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  const blockWords = new Uint32Array(16);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) blockWords[i] = view.getUint32(off + i * 4, false);
    sha256Compress(state, blockWords);
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) outView.setUint32(i * 4, state[i], false);
  return out;
}

async function pbkdf2Sha256Fallback(pwBytes, saltBytes, iterations) {
  let keyBytes = pwBytes;
  if (keyBytes.length > 64) keyBytes = sha256Bytes(keyBytes);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const kb = i < keyBytes.length ? keyBytes[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  const initState = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  const ipadWords = new Uint32Array(16);
  const opadWords = new Uint32Array(16);
  const ivIpad = new DataView(ipad.buffer);
  const ivOpad = new DataView(opad.buffer);
  for (let i = 0; i < 16; i++) {
    ipadWords[i] = ivIpad.getUint32(i * 4, false);
    opadWords[i] = ivOpad.getUint32(i * 4, false);
  }
  const innerMid = new Uint32Array(initState);
  const outerMid = new Uint32Array(initState);
  sha256Compress(innerMid, ipadWords);
  sha256Compress(outerMid, opadWords);

  // First HMAC(key, salt || INT(1))
  const firstMsg = new Uint8Array(ipad.length + saltBytes.length + 4);
  firstMsg.set(ipad, 0);
  firstMsg.set(saltBytes, 64);
  firstMsg[64 + saltBytes.length + 3] = 1;
  const innerHash1 = sha256Bytes(firstMsg);
  const outerMsg1 = new Uint8Array(64 + 32);
  outerMsg1.set(opad, 0);
  outerMsg1.set(innerHash1, 64);
  const uBytes = sha256Bytes(outerMsg1);

  const U = new Uint32Array(8);
  const T = new Uint32Array(8);
  const uView = new DataView(uBytes.buffer);
  for (let i = 0; i < 8; i++) {
    U[i] = uView.getUint32(i * 4, false);
    T[i] = U[i];
  }

  const block = new Uint32Array(16);
  const state = new Uint32Array(8);
  const chunkSize = 50000;

  for (let iter = 1; iter < iterations; iter++) {
    state.set(innerMid);
    for (let i = 0; i < 8; i++) block[i] = U[i];
    block[8] = 0x80000000;
    block[9] = 0; block[10] = 0; block[11] = 0; block[12] = 0; block[13] = 0; block[14] = 0;
    block[15] = 768;
    sha256Compress(state, block);

    for (let i = 0; i < 8; i++) block[i] = state[i];
    state.set(outerMid);
    sha256Compress(state, block);

    for (let i = 0; i < 8; i++) {
      U[i] = state[i];
      T[i] ^= U[i];
    }
    if (iter % chunkSize === 0) {
      await new Promise(r => setTimeout(r, 0));
    }
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) outView.setUint32(i * 4, T[i], false);
  return out;
}

// Pure-JS AES-256 + GCM implementation for file:// fallback
const AES_SBOX = new Uint8Array(256);
const AES_RCON = new Uint8Array([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);
(function initAesTables() {
  const p = new Uint8Array(256), q = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    p[i] = x;
    q[x] = i;
    x ^= (x << 1) ^ ((x & 0x80) ? 0x11b : 0);
  }
  AES_SBOX[0] = 0x63;
  for (let i = 1; i < 256; i++) {
    let y = p[255 - q[i]];
    let s = y;
    for (let r = 1; r <= 4; r++) s ^= ((y << r) | (y >>> (8 - r))) & 0xff;
    AES_SBOX[i] = s ^ 0x63;
  }
})();

function gfMul2(a) {
  return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
}

function aes256ExpandKey(key32) {
  const w = new Uint8Array(240);
  w.set(key32);
  const temp = new Uint8Array(4);
  for (let i = 8; i < 60; i++) {
    temp.set(w.subarray((i - 1) * 4, i * 4));
    if (i % 8 === 0) {
      const t = temp[0];
      temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[i / 8];
      temp[1] = AES_SBOX[temp[2]];
      temp[2] = AES_SBOX[temp[3]];
      temp[3] = AES_SBOX[t];
    } else if (i % 8 === 4) {
      for (let j = 0; j < 4; j++) temp[j] = AES_SBOX[temp[j]];
    }
    for (let j = 0; j < 4; j++) {
      w[i * 4 + j] = w[(i - 8) * 4 + j] ^ temp[j];
    }
  }
  return w;
}

function aes256EncryptBlock(block16, roundKeys) {
  const s = new Uint8Array(block16);
  for (let i = 0; i < 16; i++) s[i] ^= roundKeys[i];
  const tmp = new Uint8Array(16);

  for (let round = 1; round <= 14; round++) {
    for (let i = 0; i < 16; i++) tmp[i] = AES_SBOX[s[i]];
    // ShiftRows
    s[0] = tmp[0]; s[4] = tmp[4]; s[8] = tmp[8]; s[12] = tmp[12];
    s[1] = tmp[5]; s[5] = tmp[9]; s[9] = tmp[13]; s[13] = tmp[1];
    s[2] = tmp[10]; s[6] = tmp[14]; s[10] = tmp[2]; s[14] = tmp[6];
    s[3] = tmp[15]; s[7] = tmp[3]; s[11] = tmp[7]; s[15] = tmp[11];

    if (round < 14) {
      for (let c = 0; c < 16; c += 4) {
        const a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
        const sum = a0 ^ a1 ^ a2 ^ a3;
        s[c] ^= sum ^ gfMul2(a0 ^ a1);
        s[c + 1] ^= sum ^ gfMul2(a1 ^ a2);
        s[c + 2] ^= sum ^ gfMul2(a2 ^ a3);
        s[c + 3] ^= sum ^ gfMul2(a3 ^ a0);
      }
    }
    const roff = round * 16;
    for (let i = 0; i < 16; i++) s[i] ^= roundKeys[roff + i];
  }
  return s;
}

function ghashMul(X, Y) {
  const Z = new Uint8Array(16);
  const V = new Uint8Array(Y);
  for (let i = 0; i < 128; i++) {
    if ((X[i >>> 3] >>> (7 - (i & 7))) & 1) {
      for (let j = 0; j < 16; j++) Z[j] ^= V[j];
    }
    const lsb = V[15] & 1;
    for (let j = 15; j > 0; j--) V[j] = (V[j] >>> 1) | ((V[j - 1] & 1) << 7);
    V[0] >>>= 1;
    if (lsb) V[0] ^= 0xe1;
  }
  return Z;
}

function ghashCompute(H, ciphertext) {
  let Y = new Uint8Array(16);
  const block = new Uint8Array(16);
  for (let off = 0; off < ciphertext.length; off += 16) {
    block.fill(0);
    block.set(ciphertext.subarray(off, Math.min(off + 16, ciphertext.length)));
    for (let i = 0; i < 16; i++) Y[i] ^= block[i];
    Y = ghashMul(Y, H);
  }
  // Length block (AAD = 0 bits, Ciphertext = ciphertext.length * 8 bits)
  block.fill(0);
  const bitLen = ciphertext.length * 8;
  const dv = new DataView(block.buffer);
  dv.setUint32(12, bitLen >>> 0, false);
  dv.setUint32(8, Math.floor(bitLen / 0x100000000), false);
  for (let i = 0; i < 16; i++) Y[i] ^= block[i];
  return ghashMul(Y, H);
}

function aes256GcmCryptFallback(key32, nonce12, inputBytes) {
  const rk = aes256ExpandKey(key32);
  const H = aes256EncryptBlock(new Uint8Array(16), rk);
  const J0 = new Uint8Array(16);
  J0.set(nonce12, 0);
  J0[15] = 1;

  const out = new Uint8Array(inputBytes.length);
  const ctr = new Uint8Array(J0);
  const dv = new DataView(ctr.buffer);
  let counterVal = 2;

  for (let off = 0; off < inputBytes.length; off += 16) {
    dv.setUint32(12, counterVal >>> 0, false);
    counterVal++;
    const ks = aes256EncryptBlock(ctr, rk);
    const chunkLen = Math.min(16, inputBytes.length - off);
    for (let i = 0; i < chunkLen; i++) {
      out[off + i] = inputBytes[off + i] ^ ks[i];
    }
  }
  return { out, rk, H, J0 };
}

function aes256GcmEncryptFallback(key32, nonce12, ptBytes) {
  const { out: ciphertext, rk, H, J0 } = aes256GcmCryptFallback(key32, nonce12, ptBytes);
  const S = ghashCompute(H, ciphertext);
  const encJ0 = aes256EncryptBlock(J0, rk);
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) tag[i] = S[i] ^ encJ0[i];
  return { ciphertext, tag };
}

function aes256GcmDecryptFallback(key32, nonce12, ciphertext, tag) {
  const rk = aes256ExpandKey(key32);
  const H = aes256EncryptBlock(new Uint8Array(16), rk);
  const J0 = new Uint8Array(16);
  J0.set(nonce12, 0);
  J0[15] = 1;

  const S = ghashCompute(H, ciphertext);
  const encJ0 = aes256EncryptBlock(J0, rk);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= (tag[i] ^ (S[i] ^ encJ0[i]));
  if (diff !== 0) throw new Error("GCM authentication tag mismatch");

  const { out: plaintext } = aes256GcmCryptFallback(key32, nonce12, ciphertext);
  return plaintext;
}

const HAS_SUBTLE = Boolean(window.crypto && window.crypto.subtle);

// ============================================================================
// DOM ELEMENTS & MODAL
// ============================================================================
const statusText = document.getElementById("statusText");
const modalOverlay = document.getElementById("modalOverlay");
const modalTitle = document.getElementById("modalTitle");
const modalMessage = document.getElementById("modalMessage");
const modalCloseBtn = document.getElementById("modalCloseBtn");

function showModal(title, message) {
  modalTitle.textContent = title;
  modalMessage.textContent = message;
  modalOverlay.classList.remove("hidden");
}

modalCloseBtn.addEventListener("click", () => {
  modalOverlay.classList.add("hidden");
});

// ============================================================================
// TABS & THEME SWITCHING
// ============================================================================
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.target).classList.add("active");
  });
});

document.querySelectorAll(".sub-tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".sub-tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".sub-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.subtarget).classList.add("active");
  });
});

const themeToggle = document.getElementById("themeToggle");
const themeLabel = document.getElementById("themeLabel");
themeToggle.addEventListener("change", () => {
  const mode = themeToggle.checked ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", mode);
  themeLabel.textContent = themeToggle.checked ? "Dark mode" : "Light mode";
});

// Visibility Toggle Buttons
document.querySelectorAll("[data-toggle-vis]").forEach(btn => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.toggleVis);
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    btn.textContent = isHidden ? "🙈 Hide" : "👁 Show";
  });
});

// ============================================================================
// UNIQUE-CHARACTER PASSWORD & PASSPHRASE GENERATOR
// ============================================================================
const lenSlider = document.getElementById("lenSlider");
const lenLabel = document.getElementById("lenLabel");
const wordsSlider = document.getElementById("wordsSlider");
const wordsLabel = document.getElementById("wordsLabel");
const chkLower = document.getElementById("chkLower");
const chkUpper = document.getElementById("chkUpper");
const chkDigits = document.getElementById("chkDigits");
const chkSymbols = document.getElementById("chkSymbols");
const chkAmbiguous = document.getElementById("chkAmbiguous");
const rawPassInput = document.getElementById("rawPassInput");

function getSelectedPools() {
  const map = chkAmbiguous.checked ? POOL_FILTERED : POOL_RAW;
  const pools = [];
  if (chkLower.checked) pools.push(map.lower);
  if (chkUpper.checked) pools.push(map.upper);
  if (chkDigits.checked) pools.push(map.digits);
  if (chkSymbols.checked) pools.push(map.symbols);
  return pools;
}

function syncUniqueSliderBounds() {
  const pools = getSelectedPools();
  const maxUnique = pools.reduce((acc, p) => acc + p.length, 0);

  if (maxUnique === 0) {
    lenLabel.textContent = "Length: 0 (Select at least one character set)";
    lenSlider.disabled = true;
    return;
  }

  const minLen = Math.min(16, maxUnique);
  const currentVal = parseInt(lenSlider.value, 10) || 20;
  const clampedVal = Math.max(minLen, Math.min(currentVal, maxUnique));

  lenSlider.min = minLen;
  lenSlider.max = maxUnique;
  lenSlider.value = clampedVal;
  lenSlider.disabled = maxUnique <= minLen;
  lenLabel.textContent = `Length: ${clampedVal} unique characters (Max: ${maxUnique})`;
}

[chkLower, chkUpper, chkDigits, chkSymbols, chkAmbiguous].forEach(chk => {
  chk.addEventListener("change", syncUniqueSliderBounds);
});

lenSlider.addEventListener("input", () => {
  const pools = getSelectedPools();
  const maxUnique = pools.reduce((acc, p) => acc + p.length, 0);
  lenLabel.textContent = `Length: ${lenSlider.value} unique characters (Max: ${maxUnique})`;
});

wordsSlider.addEventListener("input", () => {
  wordsLabel.textContent = `Words: ${wordsSlider.value}`;
});

document.getElementById("generateRandomBtn").addEventListener("click", () => {
  const selectedPools = getSelectedPools();
  if (selectedPools.length === 0) {
    showModal("No Character Sets", "Select at least one character set checkbox!");
    return;
  }

  syncUniqueSliderBounds();
  const maxUnique = selectedPools.reduce((acc, p) => acc + p.length, 0);
  const length = Math.min(parseInt(lenSlider.value, 10), maxUnique);

  let chosen = [];
  if (length >= selectedPools.length) {
    chosen = selectedPools.map(pool => secureChoice(pool));
    const chosenSet = new Set(chosen);
    const remainingPool = [];
    for (const pool of selectedPools) {
      for (const ch of pool) {
        if (!chosenSet.has(ch)) remainingPool.push(ch);
      }
    }
    chosen.push(...secureSample(remainingPool, length - selectedPools.length));
    secureShuffle(chosen);
  } else {
    const combinedPool = selectedPools.join("");
    chosen = secureSample(combinedPool, length);
  }

  const password = chosen.join("");
  rawPassInput.value = password;
  scheduleEntropyUpdate();
  statusText.textContent = `🔐 Generated ${password.length}-character password with 100% unique characters. Select Encrypt when ready.`;
});

document.getElementById("generatePhraseBtn").addEventListener("click", () => {
  const numWords = parseInt(wordsSlider.value, 10);
  const sepVal = document.getElementById("sepSelect").value;
  const sep = sepVal === "Space" ? " " : sepVal;
  let chosenWords = secureSample(WORD_LIST, numWords);

  if (document.getElementById("chkTitleCase").checked) {
    chosenWords = chosenWords.map(w => w.charAt(0).toUpperCase() + w.slice(1));
  }

  let phrase = chosenWords.join(sep);
  if (document.getElementById("chkAppendNum").checked) {
    const digits = chkAmbiguous.checked ? POOL_FILTERED.digits : POOL_RAW.digits;
    const symbols = chkAmbiguous.checked ? POOL_FILTERED.symbols : "!@#$%&*?";
    const [d1, d2] = secureSample(digits, 2);
    const sym = secureChoice(symbols);
    phrase += `${sep}${d1}${d2}${sym}`;
  }

  rawPassInput.value = phrase;
  scheduleEntropyUpdate();
  statusText.textContent = "🔐 Passphrase generated. Select Encrypt when you are ready.";
});

// ============================================================================
// ENTROPY METER
// ============================================================================
const strengthBar = document.getElementById("strengthBar");
const entropyLabel = document.getElementById("entropyLabel");

function scheduleEntropyUpdate() {
  if (entropyDebounceId) clearTimeout(entropyDebounceId);
  entropyDebounceId = setTimeout(updateStrengthMeter, 40);
}

function updateStrengthMeter() {
  entropyDebounceId = null;
  const pw = rawPassInput.value;
  if (!pw) {
    strengthBar.style.width = "0%";
    entropyLabel.textContent = "Strength: N/A | Entropy: 0.0 bits";
    return;
  }

  const chars = new Set(pw);
  let poolSize = 0;
  let hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false, hasOther = false;

  for (const c of chars) {
    if (LOWER_SET.has(c)) hasLower = true;
    else if (UPPER_SET.has(c)) hasUpper = true;
    else if (DIGIT_SET.has(c)) hasDigit = true;
    else if (SYMBOL_SET.has(c)) hasSymbol = true;
    else if (!STANDARD_ALL_SET.has(c)) hasOther = true;
  }

  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigit) poolSize += 10;
  if (hasSymbol) poolSize += 32;
  if (hasOther) poolSize += 10;

  const entropy = poolSize > 0 ? pw.length * Math.log2(poolSize) : 0.0;
  const pct = Math.min((entropy / 160.0) * 100, 100);
  strengthBar.style.width = `${pct}%`;

  let rating, color;
  if (entropy < 60) {
    rating = "Weak";
    color = "#e03131";
  } else if (entropy < 90) {
    rating = "Moderate";
    color = "#f08c00";
  } else if (entropy < 120) {
    rating = "Strong";
    color = "#1971c2";
  } else {
    rating = "Very Strong (Cryptographic Grade)";
    color = "#2f9e44";
  }

  strengthBar.style.backgroundColor = color;
  entropyLabel.textContent = `Strength: ${rating} | Entropy: ${entropy.toFixed(1)} bits (Length: ${pw.length}, Unique: ${chars.size})`;
}

rawPassInput.addEventListener("input", scheduleEntropyUpdate);

// ============================================================================
// CRYPTO ENGINE (Web Crypto + Automatic Pure-JS Fallback for file://)
// ============================================================================
function validateMasterPassword(pw) {
  if (pw.length < 12) {
    return [false, "Master Password must be at least 12 characters long."];
  }
  const chars = new Set(pw);
  let hasL = false, hasU = false, hasD = false, hasS = false;
  for (const c of chars) {
    if (LOWER_SET.has(c)) hasL = true;
    else if (UPPER_SET.has(c)) hasU = true;
    else if (DIGIT_SET.has(c)) hasD = true;
    else if (SYMBOL_SET.has(c)) hasS = true;
  }
  if (!hasL) return [false, "Master Password must include a lowercase letter (a-z)."];
  if (!hasU) return [false, "Master Password must include an uppercase letter (A-Z)."];
  if (!hasD) return [false, "Master Password must include a digit (0-9)."];
  if (!hasS) return [false, "Master Password must include a special symbol (!@#$)."];
  return [true, ""];
}

async function deriveKeyCached(masterPw, saltBytes) {
  const pwBytes = new TextEncoder().encode(masterPw);
  const hashBytes = HAS_SUBTLE
    ? new Uint8Array(await window.crypto.subtle.digest("SHA-256", pwBytes))
    : sha256Bytes(pwBytes);

  const hashHex = Array.from(hashBytes).map(b => b.toString(16).padStart(2, "0")).join("");
  const saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, "0")).join("");
  const cacheKey = `${hashHex}:${saltHex}`;
  const genSnapshot = keyCacheGeneration;

  if (keyCache.has(cacheKey)) {
    zeroizeBuffer(pwBytes);
    return new Uint8Array(keyCache.get(cacheKey));
  }

  try {
    let derivedBytes;
    if (HAS_SUBTLE) {
      const baseKey = await window.crypto.subtle.importKey(
        "raw", pwBytes, { name: "PBKDF2" }, false, ["deriveBits"]
      );
      const derivedBits = await window.crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
        baseKey,
        256
      );
      derivedBytes = new Uint8Array(derivedBits);
    } else {
      derivedBytes = await pbkdf2Sha256Fallback(pwBytes, saltBytes, PBKDF2_ITERATIONS);
    }

    if (genSnapshot === keyCacheGeneration) {
      if (keyCache.size >= 64) {
        for (const oldBuf of keyCache.values()) zeroizeBuffer(oldBuf);
        keyCache.clear();
      }
      keyCache.set(cacheKey, new Uint8Array(derivedBytes));
    }
    return derivedBytes;
  } finally {
    zeroizeBuffer(pwBytes);
  }
}

async function aesGcmEncrypt(plaintext, masterPw) {
  const salt = getRandomBytes(16);
  const nonce = getRandomBytes(12);
  const ptBytes = new TextEncoder().encode(plaintext);
  let keyBytes = null;

  try {
    keyBytes = await deriveKeyCached(masterPw, salt);
    let ciphertext, tag;

    if (HAS_SUBTLE) {
      const cryptoKey = await window.crypto.subtle.importKey(
        "raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]
      );
      const encryptedBuf = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        cryptoKey,
        ptBytes
      );
      const encBytes = new Uint8Array(encryptedBuf);
      ciphertext = encBytes.slice(0, encBytes.length - 16);
      tag = encBytes.slice(encBytes.length - 16);
    } else {
      const res = aes256GcmEncryptFallback(keyBytes, nonce, ptBytes);
      ciphertext = res.ciphertext;
      tag = res.tag;
    }

    const combined = new Uint8Array(16 + 12 + 16 + ciphertext.length);
    combined.set(salt, 0);
    combined.set(nonce, 16);
    combined.set(tag, 28);
    combined.set(ciphertext, 44);
    return bytesToBase64Url(combined);
  } finally {
    zeroizeBuffer(ptBytes);
    if (keyBytes) zeroizeBuffer(keyBytes);
  }
}

async function aesGcmDecrypt(tokenB64, masterPw) {
  const rawPayload = base64UrlToBytes(tokenB64);
  if (rawPayload.length < 44) {
    throw new Error("Malformed AES-256-GCM payload.");
  }
  const salt = rawPayload.slice(0, 16);
  const nonce = rawPayload.slice(16, 28);
  const tag = rawPayload.slice(28, 44);
  const ciphertext = rawPayload.slice(44);

  let keyBytes = null;
  let ptBytes = null;
  try {
    keyBytes = await deriveKeyCached(masterPw, salt);
    if (HAS_SUBTLE) {
      const webCryptoInput = new Uint8Array(ciphertext.length + 16);
      webCryptoInput.set(ciphertext, 0);
      webCryptoInput.set(tag, ciphertext.length);
      const cryptoKey = await window.crypto.subtle.importKey(
        "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]
      );
      const decryptedBuf = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        cryptoKey,
        webCryptoInput
      );
      ptBytes = new Uint8Array(decryptedBuf);
    } else {
      ptBytes = aes256GcmDecryptFallback(keyBytes, nonce, ciphertext, tag);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(ptBytes);
  } finally {
    if (keyBytes) zeroizeBuffer(keyBytes);
    if (ptBytes) zeroizeBuffer(ptBytes);
  }
}

// ============================================================================
// ENCRYPT & DECRYPT UI HANDLERS
// ============================================================================
const masterKeyInput = document.getElementById("masterKeyInput");
const encryptedOutput = document.getElementById("encryptedOutput");
const encryptBtn = document.getElementById("encryptBtn");
const copyMasterBtn = document.getElementById("copyMasterBtn");
const pasteMasterBtn = document.getElementById("pasteMasterBtn");

const decryptInput = document.getElementById("decryptInput");
const decryptKeyInput = document.getElementById("decryptKeyInput");
const decryptedOutput = document.getElementById("decryptedOutput");
const decryptBtn = document.getElementById("decryptBtn");
const copyDecryptKeyBtn = document.getElementById("copyDecryptKeyBtn");
const pasteDecryptKeyBtn = document.getElementById("pasteDecryptKeyBtn");

function getEncryptMode() {
  return document.querySelector('input[name="encryptMode"]:checked').value;
}

function getDecryptMode() {
  return document.querySelector('input[name="decryptMode"]:checked').value;
}

function syncEncryptModeState() {
  const isAes = getEncryptMode() === "AES";
  masterKeyInput.disabled = !isAes;
  copyMasterBtn.disabled = !isAes;
  pasteMasterBtn.disabled = !isAes;
}

function syncDecryptModeState() {
  const isAes = getDecryptMode() === "AES";
  decryptKeyInput.disabled = !isAes;
  copyDecryptKeyBtn.disabled = !isAes;
  pasteDecryptKeyBtn.disabled = !isAes;
}

document.querySelectorAll('input[name="encryptMode"]').forEach(r => {
  r.addEventListener("change", syncEncryptModeState);
});

document.querySelectorAll('input[name="decryptMode"]').forEach(r => {
  r.addEventListener("change", syncDecryptModeState);
});

async function handleEncrypt() {
  if (isEncrypting) return;
  const rawText = rawPassInput.value;
  if (!rawText) {
    showModal("Empty Password", "Generate or enter a password first.");
    return;
  }

  if (getEncryptMode() === "B64") {
    encryptedOutput.value = utf8ToBase64(rawText);
    statusText.textContent = "🔒 Password encoded as Base64. Copy or use the result.";
    return;
  }

  const masterPw = masterKeyInput.value;
  const [valid, errMsg] = validateMasterPassword(masterPw);
  if (!valid) {
    showModal("Weak Master Password", errMsg);
    return;
  }

  isEncrypting = true;
  const opId = ++operationIds.encrypt;
  encryptBtn.disabled = true;
  encryptBtn.textContent = "Encrypting...";
  statusText.textContent = "⏳ Deriving 1M PBKDF2 key & encrypting...";

  try {
    const token = await aesGcmEncrypt(rawText, masterPw);
    if (opId === operationIds.encrypt) {
      encryptedOutput.value = token;
      statusText.textContent = "🔒 Encrypted with AES-256-GCM. Copy the token to use it in Section 03.";
    }
  } catch (err) {
    if (opId === operationIds.encrypt) {
      showModal("Encryption Error", err.message || String(err));
    }
  } finally {
    if (opId === operationIds.encrypt) {
      isEncrypting = false;
      encryptBtn.disabled = false;
      encryptBtn.textContent = "Encrypt";
    }
  }
}

async function handleDecrypt() {
  if (isDecrypting) return;
  const encryptedText = decryptInput.value.trim();
  if (!encryptedText) {
    showModal("Empty Input", "Paste an encrypted token first.");
    return;
  }

  if (getDecryptMode() === "B64") {
    try {
      decryptedOutput.value = base64ToUtf8(encryptedText);
      scheduleScreenWipe();
      statusText.textContent = "🔓 Base64 token decoded! Auto-wiping screen in 30s.";
    } catch {
      showModal("Decryption Error", "Invalid Base64 string!");
    }
    return;
  }

  const masterPw = decryptKeyInput.value;
  if (!masterPw) {
    showModal("Missing Master Key", "Enter the Master Password to decrypt this token.");
    return;
  }

  isDecrypting = true;
  const opId = ++operationIds.decrypt;
  decryptBtn.disabled = true;
  decryptBtn.textContent = "Decrypting...";
  statusText.textContent = "⏳ Verifying AES-256-GCM tag...";

  try {
    const plaintext = await aesGcmDecrypt(encryptedText, masterPw);
    if (opId === operationIds.decrypt) {
      decryptedOutput.value = plaintext;
      scheduleScreenWipe();
      statusText.textContent = "🔓 Token decrypted! Auto-wiping screen in 30s.";
    }
  } catch {
    if (opId === operationIds.decrypt) {
      decryptedOutput.value = "";
      statusText.textContent = "❌ Decryption failed: Wrong Master Password or tampered token.";
      showModal("Decryption Failed", "Incorrect Master Password or tampered AES-256-GCM token!");
    }
  } finally {
    if (opId === operationIds.decrypt) {
      isDecrypting = false;
      decryptBtn.disabled = false;
      decryptBtn.textContent = "Decrypt token";
    }
  }
}

encryptBtn.addEventListener("click", handleEncrypt);
decryptBtn.addEventListener("click", handleDecrypt);

masterKeyInput.addEventListener("keydown", e => {
  if (e.key === "Enter") handleEncrypt();
});
decryptKeyInput.addEventListener("keydown", e => {
  if (e.key === "Enter") handleDecrypt();
});

// ============================================================================
// CLIPBOARD (WITH FILE:// FALLBACK), SCREEN WIPE & RAM CACHE ZEROING
// ============================================================================
let internalClipboardFallback = "";

async function copyToClipboard(text, labelName) {
  if (!text) {
    showModal("Empty Field", `No ${labelName.toLowerCase()} to copy!`);
    return;
  }
  internalClipboardFallback = text;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      statusText.textContent = `📋 Copied ${labelName} to clipboard.`;
      return;
    }
  } catch {
    // Fall through to execCommand fallback for file:// protocol
  }

  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    document.execCommand("copy");
    statusText.textContent = `📋 Copied ${labelName} to clipboard.`;
  } catch {
    showModal("Clipboard Error", "Unable to write to system clipboard.");
  } finally {
    document.body.removeChild(ta);
  }
}

async function pasteToField(inputEl, labelName, onUpdate) {
  if (inputEl.disabled) {
    showModal("Field Disabled", `${labelName} is disabled in Base64 mode.`);
    return;
  }
  try {
    if (navigator.clipboard && navigator.clipboard.readText) {
      const text = await navigator.clipboard.readText();
      if (text) {
        inputEl.focus();
        inputEl.value = text;
        if (onUpdate) onUpdate();
        statusText.textContent = `📋 ${labelName} pasted from clipboard.`;
        return;
      }
    }
  } catch {
    // Fall through to internal clipboard fallback when opened via file://
  }

  if (internalClipboardFallback) {
    inputEl.focus();
    inputEl.value = internalClipboardFallback;
    if (onUpdate) onUpdate();
    statusText.textContent = `📋 ${labelName} pasted.`;
  } else {
    inputEl.focus();
    showModal("Paste Shortcut", "Browser blocked direct clipboard read on file:// protocol. Press Ctrl+V directly inside the focused box.");
  }
}

document.getElementById("copyRawBtn").addEventListener("click", () => copyToClipboard(rawPassInput.value, "Raw password"));
document.getElementById("pasteRawBtn").addEventListener("click", () => pasteToField(rawPassInput, "Password", scheduleEntropyUpdate));

copyMasterBtn.addEventListener("click", () => copyToClipboard(masterKeyInput.value, "Master key"));
pasteMasterBtn.addEventListener("click", () => pasteToField(masterKeyInput, "Master key"));

document.getElementById("copyEncryptedBtn").addEventListener("click", () => copyToClipboard(encryptedOutput.value, "Encrypted token"));
document.getElementById("pasteEncryptedBtn").addEventListener("click", () => pasteToField(encryptedOutput, "Encrypted token"));

document.getElementById("copyDecryptTokenBtn").addEventListener("click", () => copyToClipboard(decryptInput.value, "Encrypted token"));
document.getElementById("pasteDecryptTokenBtn").addEventListener("click", () => pasteToField(decryptInput, "Encrypted token"));

copyDecryptKeyBtn.addEventListener("click", () => copyToClipboard(decryptKeyInput.value, "Decryption key"));
pasteDecryptKeyBtn.addEventListener("click", () => pasteToField(decryptKeyInput, "Decryption key"));

document.getElementById("copyDecryptedBtn").addEventListener("click", () => copyToClipboard(decryptedOutput.value, "Decrypted password"));

function scheduleScreenWipe() {
  if (screenWipeTimerId) clearTimeout(screenWipeTimerId);
  screenWipeTimerId = setTimeout(() => {
    decryptedOutput.value = "";
    screenWipeTimerId = null;
    statusText.textContent = "🛡️ Decrypted display automatically wiped after 30s of inactivity.";
  }, 30000);
}

function clearKeyCache() {
  keyCacheGeneration++;
  for (const buf of keyCache.values()) {
    zeroizeBuffer(buf);
  }
  keyCache.clear();
}

document.getElementById("wipeScreenBtn").addEventListener("click", () => {
  if (screenWipeTimerId) {
    clearTimeout(screenWipeTimerId);
    screenWipeTimerId = null;
  }
  rawPassInput.value = "";
  decryptedOutput.value = "";
  clearKeyCache();
  updateStrengthMeter();
  statusText.textContent = "🧹 Screen text & RAM key cache zeroed. System clipboard & paste remain active.";
});

document.getElementById("clearAllBtn").addEventListener("click", () => {
  operationIds.encrypt++;
  operationIds.decrypt++;
  isEncrypting = false;
  isDecrypting = false;
  encryptBtn.disabled = false;
  encryptBtn.textContent = "Encrypt";
  decryptBtn.disabled = false;
  decryptBtn.textContent = "Decrypt token";

  if (screenWipeTimerId) {
    clearTimeout(screenWipeTimerId);
    screenWipeTimerId = null;
  }

  syncEncryptModeState();
  syncDecryptModeState();

  rawPassInput.value = "";
  masterKeyInput.value = "";
  encryptedOutput.value = "";
  decryptInput.value = "";
  decryptKeyInput.value = "";
  decryptedOutput.value = "";

  clearKeyCache();
  updateStrengthMeter();
  statusText.textContent = "🧹 All app fields and RAM keys cleared. System clipboard & paste remain active.";
});
