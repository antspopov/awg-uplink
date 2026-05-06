function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element: #${id}`);
  return el;
}

function basePath() {
  return (window.__AWG_BASE_PATH__ || "/").replace(/\/?$/, "/");
}

// NOTE: WebCrypto (crypto.subtle) is often unavailable on plain HTTP (non-secure context),
// so we use a small pure-JS SHA-256 implementation.
function sha256Hex(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }

  const maxWord = Math.pow(2, 32);
  let result = "";

  const words = [];
  let asciiBitLength = ascii.length * 8;

  let hash = sha256Hex.h || [];
  let k = sha256Hex.k || [];
  let primeCounter = k.length;

  const isComposite = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
      hash[primeCounter] = (Math.pow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (Math.pow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  sha256Hex.h = hash;
  sha256Hex.k = k;

  ascii += "\x80";
  while ((ascii.length % 64) - 56) ascii += "\x00";
  for (let i = 0; i < ascii.length; i++) {
    const j = ascii.charCodeAt(i);
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words.length] = (asciiBitLength / maxWord) | 0;
  words[words.length] = asciiBitLength;

  for (let j = 0; j < words.length; ) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash.slice(0);

    for (let i = 0; i < 64; i++) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];

      const a = hash[0];
      const e = hash[4];
      const temp1 =
        hash[7] +
        (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
        ((e & hash[5]) ^ (~e & hash[6])) +
        k[i] +
        (w[i] =
          i < 16
            ? w[i]
            : (w[i - 16] +
                (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                w[i - 7] +
                (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) |
              0);
      const temp2 =
        (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
        ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
      hash.pop();
    }

    for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
  }

  for (let i = 0; i < 8; i++) {
    for (let j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? "0" : "") + b.toString(16);
    }
  }

  return Promise.resolve(result);
}

function randomHex(nBytes) {
  const a = new Uint8Array(nBytes);
  crypto.getRandomValues(a);
  return Array.from(a)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function digestLogin(username, password) {
  const bp = basePath();
  const ch = await fetch(`${bp}api/auth/challenge`, { credentials: "include" });
  if (!ch.ok) throw new Error(`challenge failed: HTTP ${ch.status}`);
  const challenge = await ch.json();

  const realm = challenge.realm;
  const nonce = challenge.nonce;
  const qop = challenge.qop;
  const algorithm = challenge.algorithm;
  if (algorithm !== "SHA-256") throw new Error(`unsupported algorithm: ${algorithm}`);

  const method = "POST";
  const uri = `${bp}api/auth/login`;
  const nc = "00000001";
  const cnonce = randomHex(16);

  const ha1 = await sha256Hex(`${username}:${realm}:${password}`);
  const ha2 = await sha256Hex(`${method}:${uri}`);
  const response = await sha256Hex(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);

  const res = await fetch(uri, {
    method,
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({
      username,
      nonce,
      realm,
      qop,
      algorithm,
      nc,
      cnonce,
      uri,
      method,
      response,
    }),
  });

  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`login failed: HTTP ${res.status} ${t}`);
  }
}

function nextTarget() {
  const u = new URL(window.location.href);
  const next = u.searchParams.get("next");
  if (next && next.startsWith("/")) return next;
  return basePath();
}

async function main() {
  const help = $("loginHelp");
  const btn = $("loginBtn");

  async function attempt() {
    btn.disabled = true;
    help.textContent = "Входим…";
    try {
      await digestLogin($("loginUser").value.trim(), $("loginPass").value);
      window.location.href = nextTarget();
    } catch (e) {
      help.textContent = String(e && e.message ? e.message : e);
      btn.disabled = false;
    }
  }

  btn.addEventListener("click", attempt);
  $("loginPass").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") attempt();
  });
  $("loginUser").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") attempt();
  });

  // If already logged in — go to app
  try {
    const me = await fetch(`${basePath()}api/auth/me`, { credentials: "include" });
    if (me.ok) window.location.href = nextTarget();
  } catch {
    // ignore
  }
}

window.addEventListener("DOMContentLoaded", main);

