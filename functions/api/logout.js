const enc = new TextEncoder();

async function sha(value) {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(/(?:^|;\s*)dmc_session=([^;]+)/);

    if (match && env.DB) {
      const token = decodeURIComponent(match[1]);
      const tokenHash = await sha(token);

      await env.DB.prepare(
        "DELETE FROM sessions WHERE token_hash = ?"
      ).bind(tokenHash).run();
    }

    return new Response(
      JSON.stringify({ ok: true }),
      {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Set-Cookie": "dmc_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
        }
      }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ ok: false }),
      { status: 500 }
    );
  }
}
