function getCookie(cookieHeader, name) {
  const cookies = (cookieHeader || "")
    .split(";")
    .map((cookie) => cookie.trim());

  const matchingCookie = cookies.find((cookie) =>
    cookie.startsWith(name + "=")
  );

  return matchingCookie
    ? decodeURIComponent(
        matchingCookie.substring(name.length + 1)
      )
    : "";
}

module.exports = async function handler(req, res) {
  const { code, state } = req.query;

  const expectedState = getCookie(
    req.headers.cookie,
    "oauth_state"
  );

  const clientId =
    process.env.OAUTH_GITHUB_CLIENT_ID;

  const clientSecret =
    process.env.OAUTH_GITHUB_CLIENT_SECRET;

  if (!code) {
    return res
      .status(400)
      .send("GitHub did not return an authorization code.");
  }

  if (
    !state ||
    !expectedState ||
    state !== expectedState
  ) {
    return res
      .status(400)
      .send(
        "Invalid OAuth state. Please restart the login process."
      );
  }

  if (!clientId || !clientSecret) {
    return res
      .status(500)
      .send("OAuth environment variables are missing.");
  }

  try {
    const tokenResponse = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code: code
        })
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      console.error(
        "GitHub OAuth response:",
        tokenData
      );

      return res
        .status(401)
        .send("GitHub did not return an access token.");
    }

    const accessToken = tokenData.access_token;

    res.setHeader("Set-Cookie", [
      "oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
      "oauth_origin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
    ]);

    res.setHeader(
      "Content-Type",
      "text/html; charset=utf-8"
    );

    return res.status(200).send(`
      <!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">

        <meta
          name="viewport"
          content="width=device-width, initial-scale=1"
        >

        <title>Authentication Successful</title>

        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: #07111f;
            color: #edf6ff;
            font-family: Arial, sans-serif;
          }

          .message {
            width: min(440px, 80%);
            padding: 32px;
            text-align: center;
            background: #0d1c2e;
            border: 1px solid #20374e;
            border-radius: 14px;
          }

          h1 {
            margin-top: 0;
          }

          p {
            color: #95a8bc;
            line-height: 1.6;
          }
        </style>
      </head>

      <body>
        <div class="message">
          <h1>Authentication successful</h1>

          <p>
            Returning to the portfolio dashboard.
          </p>
        </div>

        <script>
          (function () {
            var content = {
              token: ${JSON.stringify(accessToken)},
              provider: "github"
            };

            var completed = false;

            function receiveMessage(event) {
              if (
                completed ||
                !window.opener ||
                window.opener.closed
              ) {
                return;
              }

              completed = true;

              window.opener.postMessage(
                "authorization:github:success:" +
                JSON.stringify(content),
                event.origin
              );

              setTimeout(function () {
                window.close();
              }, 1000);
            }

            window.addEventListener(
              "message",
              receiveMessage,
              false
            );

            function beginHandshake() {
              if (
                window.opener &&
                !window.opener.closed &&
                !completed
              ) {
                window.opener.postMessage(
                  "authorizing:github",
                  "*"
                );
              }
            }

            beginHandshake();

            var handshakeInterval =
              setInterval(function () {
                if (completed) {
                  clearInterval(handshakeInterval);
                  return;
                }

                beginHandshake();
              }, 500);

            setTimeout(function () {
              clearInterval(handshakeInterval);
            }, 15000);
          })();
        <\/script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error(
      "OAuth callback error:",
      error
    );

    return res
      .status(500)
      .send(
        "OAuth callback failed. Check the Vercel logs."
      );
  }
};
