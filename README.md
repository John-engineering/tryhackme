# Meridian Trust Bank — vulnerable practice target

A deliberately insecure "bank" web app for practising web hacking on your own
machine, TryHackMe / CTF style. It looks like a real online bank — landing
page, sign up, sign in, account dashboard with balances and transfers — and it
hides a **developer console** you're meant to break into.

> ⚠️ **This app is intentionally broken.** Every "vulnerability" here is on
> purpose. Run it locally only. Never expose it to a network, and never copy
> this code into anything real.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000. The database (`bank.db`) is created and
seeded on first run. Delete it to reset.

## The challenge

1. Create an account and sign in — a normal customer.
2. There's an internal **developer console** somewhere in this app. Find it.
3. Get in. When you do, it hands you the flag and dumps the user table.
4. Bonus: the dump contains password digests. Recover the admin's real
   password and sign in as the actual `admin` user.

The vulnerabilities are chained and none is a single obvious button. You'll
need to combine recon, reading the client-side code, inspecting your session,
and abusing a couple of API calls. Everything you need is reachable from a
browser and its dev tools — no external tooling required (though a wordlist
helps for the bonus).

## What's in scope (the techniques this teaches)

- **Recon** of paths a site would rather you didn't visit.
- **Reading client-side JavaScript** for leftover developer notes.
- **Inspecting and tampering with your session token** — the classic
  *unsigned-JWT / `alg:none`* trap.
- **Broken object-level authorization (IDOR)** in the account API.
- **Broken function-level authorization** in the transfer API.
- **Weak password storage** — unsalted SHA-256 you can crack offline.

## Reset

```bash
rm bank.db && python app.py
```

## Stuck?

A full step-by-step walkthrough lives in [`SOLUTION.md`](SOLUTION.md).
Try to avoid it — the point is to find these yourself.
