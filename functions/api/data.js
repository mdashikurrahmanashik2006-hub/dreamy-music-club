
const enc = new TextEncoder();

async function sha(value) {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function out(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

function tok(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)dmc_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function isAdmin(request, env) {
  const token = tok(request);
  if (!token) return false;

  const tokenHash = await sha(token);
  const session = await env.DB.prepare(
    "SELECT token_hash FROM sessions WHERE token_hash = ? AND expires_at > ?"
  ).bind(tokenHash, Math.floor(Date.now() / 1000)).first();

  return !!session;
}

export async function onRequestGet({ env }) {
  try {
    const members = await env.DB.prepare(
      "SELECT id, name, role, created_at FROM members ORDER BY created_at DESC"
    ).all();

    const notices = await env.DB.prepare(
      "SELECT id, title, body, date, created_at FROM notices ORDER BY created_at DESC"
    ).all();

    const gallery = await env.DB.prepare(
      "SELECT id, title, url, created_at FROM gallery ORDER BY created_at DESC"
    ).all();

    const setting = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = 'groupUrl'"
    ).first();

    return out({
      ok: true,
      members: members.results,
      notices: notices.results,
      gallery: gallery.results,
      groupUrl: setting?.value || "https://www.facebook.com/"
    });
  } catch (error) {
    return out({ ok: false, message: "ডেটা লোড করা যায়নি।" }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const origin = request.headers.get("Origin");
    if (origin && new URL(origin).host !== new URL(request.url).host) {
      return out({ ok: false, message: "অনুমতি নেই।" }, 403);
    }

    if (!(await isAdmin(request, env))) {
      return out({ ok: false, message: "Admin Login প্রয়োজন।" }, 401);
    }

    const body = await request.json();
    const action = body.action;

    if (action === "setGroupUrl") {
      const url = new URL(body.url);
      if (!["http:", "https:"].includes(url.protocol)) {
        return out({ ok: false, message: "সঠিক URL দিন।" }, 400);
      }

      await env.DB.prepare(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('groupUrl', ?)"
      ).bind(url.href).run();

      return out({ ok: true });
    }

    const types = ["members", "notices", "gallery"];
    const type = body.type;

    if (!types.includes(type)) {
      return out({ ok: false, message: "ভুল আইটেমের ধরন।" }, 400);
    }

    const tables = {
      members: "members",
      notices: "notices",
      gallery: "gallery"
    };

    const table = tables[type];

    if (action === "delete") {
      if (!body.id) return out({ ok: false, message: "ID প্রয়োজন।" }, 400);

      await env.DB.prepare(
        `DELETE FROM ${table} WHERE id = ?`
      ).bind(body.id).run();

      return out({ ok: true });
    }

    if (action === "add" || action === "edit") {
      const item = body.item || {};
      const id = body.id || crypto.randomUUID();
      const now = new Date().toISOString();

      if (type === "members") {
        const name = String(item.name || "").trim();
        const role = String(item.role || "Member").trim();

        if (!name) return out({ ok: false, message: "সদস্যের নাম দিন।" }, 400);

        if (action === "add") {
          await env.DB.prepare(
            "INSERT INTO members (id, name, role, created_at) VALUES (?, ?, ?, ?)"
          ).bind(id, name, role, now).run();
        } else {
          await env.DB.prepare(
            "UPDATE members SET name = ?, role = ? WHERE id = ?"
          ).bind(name, role, id).run();
        }
      }

      if (type === "notices") {
        const title = String(item.title || "").trim();
        const text = String(item.body || "").trim();
        const date = String(item.date || now.slice(0, 10));

        if (!title || !text) {
          return out({ ok: false, message: "শিরোনাম ও বিস্তারিত দিন।" }, 400);
        }

        if (action === "add") {
          await env.DB.prepare(
            "INSERT INTO notices (id, title, body, date, created_at) VALUES (?, ?, ?, ?, ?)"
          ).bind(id, title, text, date, now).run();
        } else {
          await env.DB.prepare(
            "UPDATE notices SET title = ?, body = ?, date = ? WHERE id = ?"
          ).bind(title, text, date, id).run();
        }
      }

      if (type === "gallery") {
        const title = String(item.title || "").trim();
        const url = String(item.url || "").trim();

        if (!title) return out({ ok: false, message: "শিরোনাম দিন।" }, 400);

        if (url) {
          try {
            const parsed = new URL(url);
            if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
          } catch {
            return out({ ok: false, message: "সঠিক URL দিন।" }, 400);
          }
        }

        if (action === "add") {
          await env.DB.prepare(
            "INSERT INTO gallery (id, title, url, created_at) VALUES (?, ?, ?, ?)"
          ).bind(id, title, url, now).run();
        } else {
          await env.DB.prepare(
            "UPDATE gallery SET title = ?, url = ? WHERE id = ?"
          ).bind(title, url, id).run();
        }
      }

      return out({ ok: true, id });
    }

    return out({ ok: false, message: "অজানা Action।" }, 400);
  } catch (error) {
    return out({ ok: false, message: "সার্ভারে সমস্যা হয়েছে।" }, 500);
  }
}
