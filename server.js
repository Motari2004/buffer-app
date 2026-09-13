import express from "express";
import session from "express-session";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Session (stores PKCE verifier + tokens) ----------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,       // set true in production behind HTTPS
      sameSite: "lax",
      maxAge: 10 * 60 * 1000, // 10 min — long enough for OAuth flow
    },
  })
);

// ---------- Static files ----------
app.use(express.static(path.join(__dirname, "public")));

// ---------- PKCE helpers ----------
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

function generateState() {
  return base64URLEncode(crypto.randomBytes(16));
}

// ---------- Routes ----------

// Root → serve index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Privacy policy
app.get("/privacy", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "privacy.html"));
});

// ---------- STEP 1: Kick off OAuth — user clicks "Connect to Buffer" ----------
app.get("/auth/buffer", (req, res) => {
  const { verifier, challenge } = generatePKCE();
  const state = generateState();

  // Store PKCE verifier + state in session (needed on callback)
  req.session.pkceVerifier = verifier;
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: process.env.BUFFER_CLIENT_ID,
    redirect_uri: process.env.BUFFER_REDIRECT_URI,
    response_type: "code",
    scope: "account:read posts:read posts:write",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "consent",
  });

  res.redirect(`https://auth.buffer.com/auth?${params.toString()}`);
});

// ---------- STEP 2: Buffer redirects back here ----------
app.get("/auth/buffer/callback", async (req, res) => {
  const { code, state, error } = req.query;

  // Handle denial / errors from Buffer
  if (error) {
    return res.status(400).send(`Authorization error: ${error}`);
  }

  // Verify state to prevent CSRF
  if (!state || state !== req.session.oauthState) {
    return res.status(400).send("Invalid state parameter. Please try again.");
  }

  const verifier = req.session.pkceVerifier;
  if (!verifier) {
    return res.status(400).send("Session expired. Please try again.");
  }

  if (!code) {
    return res.status(400).send("Missing authorization code.");
  }

  try {
    // Build token exchange body
    const body = new URLSearchParams({
      client_id: process.env.BUFFER_CLIENT_ID,
      redirect_uri: process.env.BUFFER_REDIRECT_URI,
      code,
      grant_type: "authorization_code",
      code_verifier: verifier,
    });

    // Add client_secret only if this is a Confidential client
    if (process.env.BUFFER_CLIENT_SECRET) {
      body.append("client_secret", process.env.BUFFER_CLIENT_SECRET);
    }

    const tokenRes = await fetch("https://api.buffer.com/1/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    const tokenData = await tokenRes.json();

    if (!tokenRes.ok) {
      console.error("Token exchange failed:", tokenData);
      return res.status(400).json({ error: "Token exchange failed", detail: tokenData });
    }

    // Store tokens in session
    req.session.accessToken = tokenData.access_token;
    req.session.refreshToken = tokenData.refresh_token;
    req.session.tokenExpiry = Date.now() + (tokenData.expires_in || 3600) * 1000;

    // Clear one-time PKCE data
    delete req.session.pkceVerifier;
    delete req.session.oauthState;

    res.redirect("/dashboard");
  } catch (err) {
    console.error("Token exchange error:", err);
    res.status(500).send("Server error during authentication.");
  }
});

// ---------- STEP 3: Protected dashboard ----------
app.get("/dashboard", async (req, res) => {
  if (!req.session.accessToken) {
    return res.redirect("/");
  }

  try {
    const profileRes = await fetch("https://api.buffer.com/1/user.json", {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });
    const profile = await profileRes.json();

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Dashboard – Buffer App</title>
        <link rel="stylesheet" href="/styles.css" />
      </head>
      <body>
        <main>
          <h1>Connected ✅</h1>
          <pre>${JSON.stringify(profile, null, 2)}</pre>
          <p><a href="/logout">Disconnect</a></p>
        </main>
      </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send("Failed to fetch profile from Buffer.");
  }
});

// ---------- Logout ----------
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("Session destroy error:", err);
    res.redirect("/");
  });
});

app.listen(PORT, () => {
  console.log(`✅ Running at http://localhost:${PORT}`);
});