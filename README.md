# PHANTOM Access System (starter)

This project adds real server-side access-key validation with expiry and revocation. It is a starter project, not a live hosted website.

## Included
- User key validation against the server database.
- Admin key creation with 1–3650 day expiry.
- Admin key list with status and revoke action.
- Random keys are shown once; only SHA-256 hashes are stored.
- Basic request rate limiting and security headers.
- Sensitivity controls are ordinary manual settings; no game modification is included.

## Run locally
1. Install Node.js 20 or newer on a computer.
2. Extract this ZIP and open a terminal in this folder.
3. Install dependencies: `npm install`
4. Set a strong admin password (at least 16 characters):
   - macOS/Linux: `export ADMIN_PASSWORD='use-a-long-random-secret-here'`
   - Windows PowerShell: `$env:ADMIN_PASSWORD='use-a-long-random-secret-here'`
5. Start: `npm start`
6. Open `http://localhost:3000`
7. Open `http://localhost:3000/?admin=1` to show the admin panel and sign in with `ADMIN_PASSWORD`.

## Important hosting notes
- This is not online until you deploy the backend and frontend to a server that supports Node.js and persistent storage.
- The SQLite database is saved as `phantom.sqlite` in the project folder by default. Choose persistent storage on your host, or configure `DB_PATH`.
- Use HTTPS in production. Never put `ADMIN_PASSWORD` in the HTML, in public source code, or in a public repository. Set it as a private environment variable in the hosting dashboard.
- Do not expose this admin panel to the public without a strong password and HTTPS. Consider stronger admin authentication, backups, monitoring, and dependency updates before real production use.
- If a host uses ephemeral storage, SQLite data may disappear after redeploy/restart; use persistent disk or a managed database.
- The website does not alter Free Fire files or interact with the game process.

Security reference: Express recommends TLS, security headers, and validating user input. See https://expressjs.com/advanced/best-practice-security/
