import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs/promises";
import dotenv from "dotenv";
import pg from "pg";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// 1. DATABASE CONNECTION
// ============================================================
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 1,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ============================================================
// 2. AUTO-MIGRATION (runs once per cold start)
// ============================================================
let dbReady = null;

function initDatabase() {
  if (dbReady) return dbReady;

  dbReady = (async () => {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS buffer_accounts (
          id SERIAL PRIMARY KEY,
          buffer_user_id TEXT UNIQUE NOT NULL,
          email TEXT NOT NULL,
          name TEXT,
          avatar TEXT,
          access_token TEXT NOT NULL,
          refresh_token TEXT NOT NULL,
          token_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
      `);

      await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_buffer_user_id
        ON buffer_accounts(buffer_user_id);
      `);

      console.log("✅ Database tables ready");
    } catch (err) {
      console.error("❌ Database init failed:", err.message);
      dbReady = null; // allow retry on next request
      throw err;
    }
  })();

  return dbReady;
}

// Kick off migration at module load
await initDatabase();

// ============================================================
// 3. MIDDLEWARE
// ============================================================
app.use(cookieParser(process.env.SESSION_SECRET || "dev-secret"));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

// ============================================================
// 4. PKCE & STATE HELPERS
// ============================================================
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

const OAUTH_COOKIE_OPTS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  signed: true,
  maxAge: 10 * 60 * 1000, // 10 minutes
  path: "/",
};

// ============================================================
// 5. BUFFER API HELPERS
// ============================================================
async function bufferQuery(accessToken, query, variables = {}) {
  const res = await fetch("https://api.buffer.com", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ query, variables }),
  });

  const data = await res.json();

  if (data.errors) {
    if (data.errors.some((e) => /unauthorized/i.test(e.message))) {
      const err = new Error("Unauthorized");
      err.code = "UNAUTHORIZED";
      throw err;
    }
    throw new Error(data.errors.map((e) => e.message).join("; "));
  }

  return data.data;
}

async function refreshBufferToken(refreshToken) {
  const res = await fetch("https://auth.buffer.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: process.env.BUFFER_CLIENT_ID,
      client_secret: process.env.BUFFER_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`Refresh failed: ${errBody}`);
  }

  return res.json();
}

// ============================================================
// 6. ROUTES
// ============================================================

// Home
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Privacy Policy
app.get("/privacy", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "privacy.html"));
});

// ---------- STEP 1: Initiate OAuth ----------
app.get("/auth/buffer", (req, res) => {
  const { verifier, challenge } = generatePKCE();
  const state = generateState();

  res.cookie("oauth_state", state, OAUTH_COOKIE_OPTS);
  res.cookie("pkce_verifier", verifier, OAUTH_COOKIE_OPTS);

  const params = new URLSearchParams({
    client_id: process.env.BUFFER_CLIENT_ID,
    redirect_uri: process.env.BUFFER_REDIRECT_URI,
    response_type: "code",
    scope:
      "posts:write posts:read ideas:read ideas:write account:read account:write offline_access",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "consent",
  });

  res.redirect(`https://auth.buffer.com/auth?${params.toString()}`);
});

// ---------- STEP 2: OAuth Callback ----------
app.get("/auth/buffer/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) return res.status(400).send(`Authorization error: ${error}`);

  const storedState = req.signedCookies?.oauth_state;
  const verifier = req.signedCookies?.pkce_verifier;

  if (!state || !storedState || state !== storedState) {
    return res.status(400).send("Invalid state. Try again.");
  }
  if (!verifier) return res.status(400).send("Missing PKCE verifier.");

  try {
    await initDatabase();

    // Exchange code for tokens
    const tokenRes = await fetch("https://auth.buffer.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.BUFFER_CLIENT_ID,
        client_secret: process.env.BUFFER_CLIENT_SECRET,
        redirect_uri: process.env.BUFFER_REDIRECT_URI,
        code,
        grant_type: "authorization_code",
        code_verifier: verifier,
      }),
    });

    const tokenData = await tokenRes.json();

    if (!tokenRes.ok) {
      console.error("Token exchange failed:", tokenData);
      return res
        .status(400)
        .json({ error: "Token exchange failed", detail: tokenData });
    }

    // Fetch user identity
    const accountData = await bufferQuery(
      tokenData.access_token,
      `query { account { id email name avatar } }`
    );
    const acct = accountData.account;

    // Upsert into DB
    await pool.query(
      `INSERT INTO buffer_accounts
        (buffer_user_id, email, name, avatar, access_token, refresh_token, token_expires_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '1 second' * $7, NOW())
       ON CONFLICT (buffer_user_id) DO UPDATE SET
         email = EXCLUDED.email,
         name = EXCLUDED.name,
         avatar = EXCLUDED.avatar,
         access_token = EXCLUDED.access_token,
         refresh_token = EXCLUDED.refresh_token,
         token_expires_at = EXCLUDED.token_expires_at,
         updated_at = NOW()`,
      [
        acct.id,
        acct.email,
        acct.name,
        acct.avatar || null,
        tokenData.access_token,
        tokenData.refresh_token,
        tokenData.expires_in,
      ]
    );

    res.clearCookie("oauth_state", { path: "/" });
    res.clearCookie("pkce_verifier", { path: "/" });

    res.redirect("/dashboard");
  } catch (err) {
    console.error("Callback error:", err);
    res.status(500).send("Authentication failed.");
  }
});

// ---------- STEP 3: Multi-Account Dashboard ----------
app.get("/dashboard", async (req, res) => {
  try {
    await initDatabase();

    // 1. Load all connected accounts
    const { rows: accounts } = await pool.query(
      `SELECT buffer_user_id, email, name, avatar, access_token, refresh_token, token_expires_at
       FROM buffer_accounts ORDER BY updated_at DESC`
    );

    if (accounts.length === 0) {
      return res.redirect("/");
    }

    // 2. Refresh expiring tokens (within 5 min)
    const now = Date.now();
    for (const acct of accounts) {
      const expiresAt = new Date(acct.token_expires_at).getTime();
      if (expiresAt - now < 5 * 60 * 1000) {
        try {
          const refreshed = await refreshBufferToken(acct.refresh_token);

          await pool.query(
            `UPDATE buffer_accounts SET
               access_token = $1,
               refresh_token = $2,
               token_expires_at = NOW() + INTERVAL '1 second' * $3,
               updated_at = NOW()
             WHERE buffer_user_id = $4`,
            [
              refreshed.access_token,
              refreshed.refresh_token,
              refreshed.expires_in,
              acct.buffer_user_id,
            ]
          );

          acct.access_token = refreshed.access_token;
        } catch (err) {
          console.error(`Refresh failed for ${acct.email}:`, err.message);
        }
      }
    }

    // 3. Fetch Buffer data for each account in parallel
    const accountData = await Promise.all(
      accounts.map(async (acct) => {
        try {
          const data = await bufferQuery(
            acct.access_token,
            `
            query {
              account {
                id email name avatar
                organizations {
                  id name
                  channels { id name service displayName avatar isDisconnected }
                }
              }
            }
          `
          );

          const orgs = data.account.organizations || [];
          const channels = orgs.flatMap((o) => o.channels);

          return {
            bufferUserId: acct.buffer_user_id,
            email: data.account.email,
            name: data.account.name,
            avatar: data.account.avatar,
            organizations: orgs.map((o) => ({ id: o.id, name: o.name })),
            channels: channels.map((c) => ({
              id: c.id,
              name: c.name || c.displayName,
              service: c.service,
              avatar: c.avatar,
              isDisconnected: c.isDisconnected,
            })),
            error: null,
          };
        } catch (err) {
          return {
            bufferUserId: acct.buffer_user_id,
            email: acct.email,
            name: acct.name,
            avatar: acct.avatar,
            organizations: [],
            channels: [],
            error: err.message,
          };
        }
      })
    );

    // 4. Inject data into HTML
    const pageData = {
      accounts: accountData,
      accountCount: accountData.length,
      totalChannels: accountData.reduce((s, a) => s + a.channels.length, 0),
      fetchedAt: new Date().toISOString(),
    };

    const htmlPath = path.join(__dirname, "public", "dashboard.html");
    let html = await fs.readFile(htmlPath, "utf-8");

    const safeJson = JSON.stringify(pageData).replace(/</g, "\\u003c");
    html = html.replace(
      "<!-- __INITIAL_DATA__ -->",
      `<script>window.__INITIAL_DATA__ = ${safeJson};</script>`
    );

    res.set("Content-Type", "text/html").send(html);
  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).send(`Dashboard failed: ${err.message}`);
  }
});

// ---------- Disconnect One Account ----------
app.post("/disconnect/:bufferUserId", async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM buffer_accounts WHERE buffer_user_id = $1",
      [req.params.bufferUserId]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- Logout All ----------
app.get("/logout", async (req, res) => {
  try {
    await pool.query("DELETE FROM buffer_accounts");
  } catch (err) {
    console.error("Logout error:", err);
  }
  res.redirect("/");
});

// ============================================================
// 7. START SERVER
// ============================================================
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});