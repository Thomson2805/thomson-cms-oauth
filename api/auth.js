const crypto = require("crypto");
module.exports = async function handler(req, res) {
  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID;
  if (!clientId) return res.status(500).send("Missing OAUTH_GITHUB_CLIENT_ID");
  const state = crypto.randomBytes(24).toString("hex");
  res.setHeader("Set-Cookie", `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`);
  const redirect = new URL("https://github.com/login/oauth/authorize");
  redirect.searchParams.set("client_id", clientId);
  redirect.searchParams.set("scope", "repo,user");
  redirect.searchParams.set("state", state);
  res.redirect(302, redirect.toString());
};
