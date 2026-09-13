# Buffer App

Minimal Node.js + Express app that authenticates with Buffer via OAuth 2.0 (PKCE).

## Setup

1. `npm install`
2. Copy `.env.example` → `.env` and fill in your Buffer client ID/secret.
3. `npm run dev`
4. Open http://localhost:3000

## Buffer App Settings

- **Privacy Policy URL:** `https://<your-host>/privacy.html`
- **Redirect URL:** `http://localhost:3000/auth/buffer/callback` (dev)
  or `https://<your-host>/auth/buffer/callback` (prod)

## Hosting the Privacy Policy for Free (GitHub Pages)

1. Create a GitHub repo (e.g. `buffer-app`).
2. Push this project.
3. Go to **Settings → Pages**, set source to `main` branch, `/root`.
4. Your policy will be live at:
   `https://<your-username>.github.io/buffer-app/public/privacy.html`

   *(Tip: move `privacy.html` to the repo root if you want a cleaner URL.)*