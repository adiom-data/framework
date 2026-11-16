import assert from "node:assert/strict";
import test from "node:test";
import { AuthTokenManager } from "../dist/auth/tokenManager.js";

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function token(subject) {
  return ["eyJhbGciOiJub25lIn0", Buffer.from(JSON.stringify({ sub: subject, exp: Math.floor(Date.now() / 1000) + 3600 })).toString("base64url"), "signature"].join(".");
}

function tokenResponse(value) {
  return new Response(JSON.stringify({ access_token: value }), { status: 200 });
}

test("logout discards a pending token and blocks fetching until logout finishes", async () => {
  const pendingToken = deferred();
  const pendingLogout = deferred();
  const fresh = token("new-user");
  let tokenRequests = 0;
  const manager = new AuthTokenManager({ fetch: async (url, options) => {
    assert.equal(options.cache, "no-store");
    if (url === "/auth/logout") return pendingLogout.promise;
    return ++tokenRequests === 1 ? pendingToken.promise : tokenResponse(fresh);
  }});
  const oldRequest = manager.getToken();
  const logout = manager.logout();
  assert.equal(await manager.getToken(), undefined);
  assert.equal(tokenRequests, 1);
  pendingToken.resolve(tokenResponse(token("old-user")));
  assert.equal(await oldRequest, undefined);
  pendingLogout.resolve(new Response(null, { status: 204 }));
  await logout;
  assert.equal(await manager.getToken(), fresh);
  assert.equal(tokenRequests, 2);
});

test("stale success, unauthorized, failed, and network responses cannot replace a newer login", async (t) => {
  for (const kind of ["success", "unauthorized", "failed", "network"]) {
    await t.test(kind, async () => {
      const old = deferred();
      const fresh = token("new-user");
      let requests = 0;
      const manager = new AuthTokenManager({ fetch: async () => ++requests === 1 ? old.promise : tokenResponse(fresh) });
      const oldRequest = manager.getToken();
      manager.clear();
      assert.equal(await manager.getToken(), fresh);
      if (kind === "network") old.reject(new Error("stale network failure"));
      else old.resolve(kind === "success" ? tokenResponse(token("old-user")) : new Response(null, { status: kind === "unauthorized" ? 401 : 500 }));
      assert.equal(await oldRequest, undefined);
      assert.equal(await manager.getToken(), fresh);
      assert.equal(requests, 2);
    });
  }
});

test("clear also invalidates a response whose JSON body is still pending", async () => {
  const body = deferred();
  const parsing = deferred();
  const manager = new AuthTokenManager({ fetch: async () => ({ status: 200, ok: true, json: () => { parsing.resolve(); return body.promise; } }) });
  const pending = manager.getToken();
  await parsing.promise;
  manager.clear();
  body.resolve({ access_token: token("old-user") });
  assert.equal(await pending, undefined);
});

test("an old request's completion does not detach a newer pending refresh", async () => {
  const old = deferred(), fresh = deferred();
  let requests = 0;
  const manager = new AuthTokenManager({ fetch: async () => ++requests === 1 ? old.promise : fresh.promise });
  const first = manager.getToken();
  manager.clear();
  const second = manager.getToken({ forceRefresh: true });
  old.resolve(tokenResponse(token("old-user")));
  assert.equal(await first, undefined);
  const third = manager.getToken();
  assert.equal(requests, 2);
  const value = token("new-user");
  fresh.resolve(tokenResponse(value));
  assert.equal(await second, value);
  assert.equal(await third, value);
});

test("concurrent forced refreshes share a request without changing authentication state", async () => {
  const response = deferred();
  let requests = 0;
  const manager = new AuthTokenManager({ fetch: async () => { requests++; return response.promise; } });
  const version = manager.authStateVersion;
  const first = manager.getToken({ forceRefresh: true });
  const second = manager.getToken({ forceRefresh: true });
  assert.equal(requests, 1);
  const value = token("same-user");
  response.resolve(tokenResponse(value));
  assert.equal(await first, value);
  assert.equal(await second, value);
  assert.equal(manager.authStateVersion, version);
});

test("logout failures are reported and pending tokens stay invalidated", async () => {
  const old = deferred();
  const manager = new AuthTokenManager({ fetch: async (url) => url === "/auth/logout" ? new Response(null, { status: 500 }) : old.promise });
  const pending = manager.getToken();
  await assert.rejects(manager.logout(), /Unable to end auth session/);
  old.resolve(tokenResponse(token("old-user")));
  assert.equal(await pending, undefined);
});

test("redirect logout invalidates pending credentials and blocks retrieval during navigation", async () => {
  const old = deferred();
  let destination;
  const manager = new AuthTokenManager({ fetch: () => old.promise });
  const pending = manager.getToken();
  manager.logoutWithRedirect({ location: { assign: value => { destination = value; } } });
  assert.equal(destination, "/auth/logout");
  old.resolve(tokenResponse(token("old-user")));
  assert.equal(await pending, undefined);
  assert.equal(await manager.getToken(), undefined);
});
