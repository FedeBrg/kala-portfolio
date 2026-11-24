/**
 * Tiny GitHub OAuth helper for Decap CMS (Cloudflare Workers, free plan).
 *
 * Decap opens  <worker>/auth  in a popup; this redirects to GitHub's login.
 * GitHub sends the user back to  <worker>/callback ; this swaps the one-time code for a token
 * and hands the token to the /admin/ page that opened the popup (and only to that site).
 *
 * Settings (Worker > Settings > Variables and Secrets):
 *   GITHUB_CLIENT_ID      (Text)    from your GitHub OAuth App
 *   GITHUB_CLIENT_SECRET  (Secret)  from your GitHub OAuth App
 *   ALLOWED_ORIGIN        (Text)    your site origin, e.g. https://your-username.github.io  (no path, no trailing slash)
 *
 * The token only carries the logged-in person's own GitHub permissions, so only people with
 * write access to the repository (you and the collaborators you add) can save anything.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/auth") {
      const state = crypto.randomUUID();
      const gh = new URL("https://github.com/login/oauth/authorize");
      gh.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
      gh.searchParams.set("redirect_uri", url.origin + "/callback");
      gh.searchParams.set("scope", url.searchParams.get("scope") === "repo" ? "repo" : "public_repo");
      gh.searchParams.set("state", state);
      return new Response(null, {
        status: 302,
        headers: {
          Location: gh.toString(),
          "Set-Cookie": `decap_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
        },
      });
    }

    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const cookie = (request.headers.get("Cookie") || "").match(/decap_oauth_state=([^;]+)/);
      if (!code || !state || !cookie || cookie[1] !== state) {
        return page("error", { message: "Login expired or was interrupted. Close this window and try again." }, env);
      }
      const res = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": "decap-oauth-worker" },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: url.origin + "/callback",
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!data.access_token) {
        return page("error", { message: data.error_description || "GitHub did not return a token." }, env);
      }
      return page("success", { token: data.access_token, provider: "github" }, env);
    }

    return new Response("Decap CMS OAuth helper is running.", { headers: { "Content-Type": "text/plain" } });
  },
};

function page(status, content, env) {
  const origin = JSON.stringify(env.ALLOWED_ORIGIN || "");
  const message = JSON.stringify(`authorization:github:${status}:${JSON.stringify(content)}`);
  const html = `<!doctype html><html><body><p>Finishing login...</p><script>
  (function () {
    var allowed = ${origin};
    function receive(e) {
      if (!allowed || e.origin !== allowed) return;
      window.removeEventListener("message", receive);
      window.opener.postMessage(${message}, e.origin);
      setTimeout(function () { window.close(); }, 200);
    }
    window.addEventListener("message", receive);
    if (window.opener) window.opener.postMessage("authorizing:github", allowed || "*");
  })();
  </script></body></html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
  });
}
