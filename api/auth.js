const crypto = require("crypto");

module.exports = async function handler(req, res) {
  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID;

  if (!clientId) {
    return res
      .status(500)
      .send("Missing OAUTH_GITHUB_CLIENT_ID");
  }

  const state = crypto.randomBytes(24).toString("hex");

  const allowedOrigin =
    process.env.ADMIN_ORIGIN ||
    "https://thomsonportofolio.vercel.app";

  const requestedOrigin =
    typeof req.query.origin === "string"
      ? req.query.origin
      : allowedOrigin;

  const origin =
    requestedOrigin === allowedOrigin
      ? requestedOrigin
      : allowedOrigin;

  res.setHeader("Set-Cookie", [
    `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
    `oauth_origin=${encodeURIComponent(origin)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
  ]);

  const githubAuthorizationUrl =
    new URL("https://github.com/login/oauth/authorize");

  githubAuthorizationUrl.searchParams.set(
    "client_id",
    clientId
  );

  githubAuthorizationUrl.searchParams.set(
    "scope",
    "repo,user"
  );

  githubAuthorizationUrl.searchParams.set(
    "state",
    state
  );

  return res.redirect(
    302,
    githubAuthorizationUrl.toString()
  );
};
