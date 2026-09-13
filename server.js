import express from "express";
import session from "express-session";
import fetch from "node-fetch";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // set true behind HTTPS in production
  })
);

app.use(express.static("public"));

// ---------- Helper: PKCE ----------
function base64URLEncode(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function generatePKCE() {
  const verifier = base64URLEncode(crypto.randomBytes(32));
  const challenge = base64URLEncode(
    crypto.createHash("sha256").update(verifier).digest()
  );
  return { verifier, challenge };
}

// ---------- Step 1: Redirect user to Buffer ----------
app.get("/auth/buffer", (req, res) => {
  const { verifier, challenge } = generatePKCE();
  req.session.pkce_verifier = verifier;

  const params = new URLSearchParams({
    client_id: process.env.BUFFER_CLIENT_ID,
    redirect_uri: process.env.BUFFER_REDIRECT_URI,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: "account:read posts:read posts:write",
  });

  res.redirect(`https://auth.buffer.com/auth?${params.toString()}`);
});

// ---------- Step 2: Handle callback from Buffer ----------
app.get("/auth/buffer/callback", async (req, res) => {
  const { code, error } = req.query;

  if (error) {
    return res.status(400).send(`Authorization error: ${error}`);
  }
  if (!code) {
    return res.status(400).send("Missing authorization code.");
  }

  const verifier = req.session.pkce_verifier;
  if (!verifier) {
    return res.status(400).send("Missing PKCE verifier. Restart the flow.");
  }

  try {
    const tokenRes = await fetch("https://api.buffer.com/1/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.BUFFER_CLIENT_ID,
        client_secret: process.env.BUFFER_CLIENT_SECRET, // omit if public client
        redirect_uri: process.env.BUFFER_REDIRECT_URI,
        code,
        grant_type: "authorization_code",
        code_verifier: verifier,
      }),
    });

    const tokenData = await tokenRes.json();

    if (!tokenRes.ok) {
      return res.status(400).json({ error: "Token exchange failed", tokenData });
    }

    // Store tokens in session (in production use a secure DB)
    req.session.access_token = tokenData.access_token;
    req.session.refresh_token = tokenData.refresh_token;

    delete req.session.pkce_verifier;

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error during token exchange.");
  }
});

// ---------- Step 3: Protected dashboard ----------
app.get("/dashboard", async (req, res) => {
  const token = req.session.access_token;
  if (!token) return res.redirect("/");

  try {
    const profileRes = await fetch("https://api.buffer.com/1/user.json", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const profile = await profileRes.json();

    res.send(`
      <h1>Connected to Buffer ✅</h1>
      <pre>${JSON.stringify(profile, null, 2)}</pre>
      <p><a href="/auth/buffer">Re-authorize</a></p>
    `);
  } catch (err) {
    res.status(500).send("Failed to fetch profile.");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});