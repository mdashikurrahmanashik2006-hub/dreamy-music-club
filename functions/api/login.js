
const enc = new TextEncoder();

async function sha(value) {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2) {
    throw new Error("Invalid hash");
  }
  return new Uint8Array(hex.match(/.{2}/g).map(x => parseInt(x, 16)));
}

async function verifyPassword(password, stored) {
  const parts = stored.split(".");
  if (parts.length !== 2) return false;

  const [saltHex, expectedHex] = parts;
  if (saltHex.length !== 32 || expectedHex.length !== 64) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: hexToBytes(saltHex),
    iterations: 310000,
    hash: "SHA-256"
  }, key, 256);

  const actual = [...new Uint8Array(bits)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return actual === expectedHex;
}

function response(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers
    }
  });
}

export async function onRequestPost({ request, env }) {
  try {
    const origin = request.headers.get("Origin");

    if (origin && new URL(origin).host !== new URL(request.url).host) {
      return response({ ok: false, message: "অনুমতি নেই।" }, 403);
    }

    if (!env.DB || !env.ADMIN_USERNAME || !env.ADMIN_PASSWORD_HASH) {
      return response({ ok: false, message: "Admin সেটিংস অসম্পূর্ণ।" }, 500);
    }

    const body = await request.json();
    const username = String(body.username || "");
    const password = String(body.password || "");

    if (!username || !password || password.length > 1024) {
      return response({ ok: false, message: "Username ও Password দিন।" }, 400);
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const ipHash = await sha(ip);
    const now = Math.floor(Date.now() / 1000);

    const attempt = await env.DB.prepare(
      "SELECT attempts, window_start, blocked_until FROM login_attempts WHERE ip_hash = ?"
    ).bind(ipHash).first();

    if (attempt && attempt.blocked_until > now) {
      return response({ ok: false, message: "কিছুক্ষণ পরে আবার চেষ্টা করুন।" }, 429);
    }

    let attempts = attempt?.attempts || 0;
    let windowStart = attempt?.window_start || now;

    if (now - windowStart > 900) {
      attempts = 0;
      windowStart = now;
    }

    const validUser = username === env.ADMIN_USERNAME;
    const validPassword = await verifyPassword(password, env.ADMIN_PASSWORD_HASH);

    if (!validUser || !validPassword) {
      attempts++;

      const blockedUntil = attempts >= 5 ? now + 900 : 0;

      await env.DB.prepare(
        "INSERT OR REPLACE INTO login_attempts (ip_hash, attempts, window_start, blocked_until) VALUES (?, ?, ?, ?)"
      ).bind(ipHash, attempts, windowStart, blockedUntil).run();

      return response({ ok: false, message: "Username অথবা Password ভুল।" }, 401);
    }

    await env.DB.prepare(
      "DELETE FROM login_attempts WHERE ip_hash = ?"
    ).bind(ipHash).run();

    const random = crypto.getRandomValues(new Uint8Array(32));
    const token = [...random]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const tokenHash = await sha(token);
    const expires = now + 60 * 60 * 24;

    await env.DB.prepare(
      "INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)"
    ).bind(tokenHash, expires).run();

    return response(
      { ok: true, message: "Login successful" },
      200,
      {
        "Set-Cookie": `dmc_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`
      }
    );
} catch (error) {
  console.error("LOGIN API ERROR:", error);
  return response({ ok: false, message: "সার্ভারে সমস্যা হয়েছে।" }, 500);
}
} 
