/* Meridian Trust — front-end helpers.
 *
 * Session tokens are standard signed JWTs stored in localStorage under
 * "mtb_token". Read Bank.whoami() if you need the current claims.
 *
 * TODO(dev): drop the alg:"none" shim from the token verifier before launch.
 *            it was only meant for the internal console harness. tracking: MTB-418
 */
window.Bank = (function () {
  const KEY = "mtb_token";

  function setToken(t) { try { localStorage.setItem(KEY, t); } catch (e) {} }
  function getToken() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function clearToken() { try { localStorage.removeItem(KEY); } catch (e) {} }

  function b64urlDecode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return atob(s);
  }

  // Decode (but do not verify) the payload of the current token.
  function whoami() {
    const t = getToken();
    if (!t) return null;
    try { return JSON.parse(b64urlDecode(t.split(".")[1])); }
    catch (e) { return null; }
  }

  async function api(path, method, body) {
    const headers = { "Content-Type": "application/json" };
    const t = getToken();
    if (t) headers["Authorization"] = "Bearer " + t;
    const res = await fetch(path, {
      method: method || "GET",
      headers: headers,
      body: body ? JSON.stringify(body) : undefined
    });
    let parsed = {};
    try { parsed = await res.json(); } catch (e) {}
    return { ok: res.ok, status: res.status, body: parsed };
  }

  return { setToken, getToken, clearToken, whoami, api };
})();
