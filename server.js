import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs/promises";
import dotenv from "dotenv";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Middleware ----------
app.use(cookieParser(process.env.SESSION_SECRET || "dev-secret-change-me"));
app.use(express.static(path.join(__dirname, "public")));

// ---------- PKCE & State Helpers ----------
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

// Cookie options for OAuth attempt data
const OAUTH_COOKIE_OPTS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  signed: true,
  maxAge: 10 * 60 * 1000, // 10 minutes
  path: "/",
};

// ---------- Routes ----------

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/privacy", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "privacy.html"));
});

// ---------- STEP 1: Initiate OAuth ----------
app.get("/auth/buffer", (req, res) => {
  const { verifier, challenge } = generatePKCE();
  const state = generateState();

  // Store verifier + state in signed cookies (serverless-safe)
  res.cookie("oauth_state", state, OAUTH_COOKIE_OPTS);
  res.cookie("pkce_verifier", verifier, OAUTH_COOKIE_OPTS);

  const params = new URLSearchParams({
    client_id: process.env.BUFFER_CLIENT_ID,
    redirect_uri: process.env.BUFFER_REDIRECT_URI,
    response_type: "code",
    scope: "account:read posts:read posts:write offline_access", // added offline_access for refresh token
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "consent",
  });

  res.redirect(`https://auth.buffer.com/auth?${params.toString()}`);
});

// ---------- STEP 2: Handle OAuth Callback ----------
app.get("/auth/buffer/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`Authorization error: ${error}`);
  }

  const storedState = req.signedCookies?.oauth_state;
  const verifier = req.signedCookies?.pkce_verifier;

  // Validate state (CSRF check)
  if (!state || !storedState || state !== storedState) {
    return res.status(400).send("Invalid state parameter. Please try again.");
  }

  if (!verifier) {
    return res
      .status(400)
      .send("Missing PKCE verifier (cookie expired or blocked). Please try again.");
  }

  if (!code) {
    return res.status(400).send("Missing authorization code.");
  }

  try {
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
      return res.status(400).json({
        error: "Token exchange failed",
        detail: tokenData,
      });
    }

    // Store tokens in signed cookies
    res.cookie("access_token", tokenData.access_token, {
      ...OAUTH_COOKIE_OPTS,
      maxAge: (tokenData.expires_in || 3600) * 1000,
    });

    if (tokenData.refresh_token) {
      res.cookie("refresh_token", tokenData.refresh_token, {
        ...OAUTH_COOKIE_OPTS,
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });
    }

    // Clear one-time OAuth cookies
    res.clearCookie("oauth_state", { path: "/" });
    res.clearCookie("pkce_verifier", { path: "/" });

    res.redirect("/dashboard");
  } catch (err) {
    console.error("Token exchange error:", err);
    res.status(500).send("Server error during authentication.");
  }
});

// ---------- STEP 3: Protected Dashboard with Data Injection ----------
app.get("/dashboard", async (req, res) => {
  const token = req.signedCookies?.access_token;

  if (!token) {
    return res.redirect("/");
  }

  try {
    const apiRes = await fetch("https://api.buffer.com", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: `
          query DashboardData {
            account {
              id
              email
              name
              organizations {
                id
                name
                channels {
                  id
                  name
                  service
                  avatar
                }
              }
            }
          }
        `,
      }),
    });

    const apiData = await apiRes.json();

    // Basic check for auth errors
    if (apiData.errors?.some((e) => /unauthorized/i.test(e.message))) {
      res.clearCookie("access_token", { path: "/" });
      return res.redirect("/");
    }

    const channels =
      apiData.data?.account?.organizations?.flatMap((org) => org.channels) || [];

    const pageData = {
      account: apiData.data?.account || {},
      channels,
      channelCount: channels.length,
      fetchedAt: new Date().toISOString(),
    };

    const htmlPath = path.join(__dirname, "public", "dashboard.html");
    let html = await fs.readFile(htmlPath, "utf-8");

    const safeJson = JSON.stringify(pageData).replace(/</g, "\\u003c");

    // The placeholder <!-- __INITIAL_DATA__ --> must exist in dashboard.html
    html = html.replace(
      "<!-- __INITIAL_DATA__ -->",
      `<script>window.__INITIAL_DATA__ = ${safeJson};</script>`
    );

    res.set("Content-Type", "text/html");
    res.send(html);
  } catch (err) {
    console.error("Dashboard fetch error:", err);
    res.status(500).send("Failed to load dashboard.");
  }
});

// ---------- Logout ----------
app.get("/logout", (req, res) => {
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/" });
  res.clearCookie("oauth_state", { path: "/" });
  res.clearCookie("pkce_verifier", { path: "/" });
  res.redirect("/");
});

// ---------- Start Server ----------
app.listen(PORT, () => {
  console.log(`✅ Running at http://localhost:${PORT}`);
});