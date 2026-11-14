function cookieValue(cookieHeader, name) {
  const entry = (cookieHeader || "").split(";").map(v => v.trim()).find(v => v.startsWith(name + "="));
  return entry ? entry.slice(name.length + 1) : "";
}
module.exports = async function handler(req, res) {
  const { code, state } = req.query;
  const expectedState = cookieValue(req.headers.cookie, "oauth_state");
  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID;
  const clientSecret = process.env.OAUTH_GITHUB_CLIENT_SECRET;
  const adminOrigin = process.env.ADMIN_ORIGIN || "https://thomson-saragih.vercel.app";
  if (!code || !state || !expectedState || state !== expectedState) return res.status(400).send("Invalid OAuth state. Start again from the CMS login page.");
  if (!clientId || !clientSecret) return res.status(500).send("OAuth environment variables are missing.");
  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Accept": "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code })
  });
  const data = await tokenResponse.json();
  if (!data.access_token) return res.status(401).send("GitHub did not return an access token.");
  const payload = JSON.stringify({ token: data.access_token, provider: "github" }).replace(/</g, "\u003c");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Set-Cookie", "oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  res.send(`<!doctype html><html><body><p>Authentication successful. This window can be closed.</p><script>
    (function(){
      var message = 'authorization:github:success:' + ${JSON.stringify(payload)};
      if (window.opener) window.opener.postMessage(message, ${JSON.stringify(adminOrigin)});
      window.close();
    })();
  <\/script></body></html>`);
};
