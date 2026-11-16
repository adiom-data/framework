import assert from "node:assert/strict";
import test from "node:test";
import { Code, ConnectError } from "@connectrpc/connect";
import { createAuthInterceptor } from "../dist/auth/connect.js";
import { AuthTokenManager } from "../dist/auth/tokenManager.js";

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function token(subject) {
  return ["eyJhbGciOiJub25lIn0", Buffer.from(JSON.stringify({ sub: subject, exp: Math.floor(Date.now() / 1000) + 3600 })).toString("base64url"), "signature"].join(".");
}

function response(value) {
  return new Response(JSON.stringify({ access_token: value }), { status: 200 });
}

test("two simultaneous unauthenticated RPCs share a refresh and both retry", async () => {
  const old = token("old"), fresh = token("fresh");
  const refresh = deferred(), refreshStarted = deferred(), initialCalls = deferred();
  const failures = [deferred(), deferred()];
  let fetches = 0;
  const manager = new AuthTokenManager({ fetch: async () => {
    if (++fetches === 1) return response(old);
    assert.equal(fetches, 2, "concurrent retries started an extra refresh");
    refreshStarted.resolve();
    return refresh.promise;
  }});
  await manager.getToken();
  const intercept = createAuthInterceptor(manager);
  const attempts = [0, 0];
  const calls = attempts.map((_, id) => intercept(async req => {
    attempts[id]++;
    if (attempts[id] === 1) {
      assert.equal(req.header.get("Authorization"), `Bearer ${old}`);
      if (attempts.every(count => count === 1)) initialCalls.resolve();
      return failures[id].promise;
    }
    assert.equal(req.header.get("Authorization"), `Bearer ${fresh}`);
    return { message: id };
  })({ header: new Headers() }));
  const results = Promise.all(calls);
  await initialCalls.promise;
  for (const failure of failures) failure.reject(new ConnectError("expired", Code.Unauthenticated));
  await refreshStarted.promise;
  refresh.resolve(response(fresh));
  assert.deepEqual((await results).map(result => result.message), [0, 1]);
  assert.deepEqual(attempts, [2, 2]);
  assert.equal(fetches, 2);
});

test("a late rejection reuses a token already refreshed by another RPC", async () => {
  const old = token("old"), fresh = token("fresh");
  const lateFailure = deferred(), started = deferred();
  let fetches = 0;
  const manager = new AuthTokenManager({ fetch: async () => {
    fetches++;
    assert.ok(fetches <= 2, "late rejection started another refresh");
    return response(fetches === 1 ? old : fresh);
  }});
  await manager.getToken();
  const intercept = createAuthInterceptor(manager);
  let lateAttempts = 0;
  const late = intercept(async req => {
    if (++lateAttempts === 1) { started.resolve(); return lateFailure.promise; }
    assert.equal(req.header.get("Authorization"), `Bearer ${fresh}`);
    return { message: "late" };
  })({ header: new Headers() });
  await started.promise;
  let earlyAttempts = 0;
  const early = intercept(async req => {
    if (++earlyAttempts === 1) throw new ConnectError("expired", Code.Unauthenticated);
    assert.equal(req.header.get("Authorization"), `Bearer ${fresh}`);
    return { message: "early" };
  })({ header: new Headers() });
  await early;
  lateFailure.reject(new ConnectError("expired", Code.Unauthenticated));
  await late;
  assert.equal(fetches, 2);
  assert.equal(earlyAttempts, 2);
  assert.equal(lateAttempts, 2);
});

test("old RPC rejections cannot refresh or replay under a newer login", async t => {
  for (const reset of ["clear", "logout"]) {
    await t.test(reset, async () => {
      const started = deferred(), failure = deferred();
      const old = token("old-user"), fresh = token("new-user");
      const unauthorized = new ConnectError("expired", Code.Unauthenticated);
      let fetches = 0, attempts = 0;
      const manager = new AuthTokenManager({ fetch: async url => {
        if (url === "/auth/logout") return new Response(null, { status: 204 });
        return response(++fetches === 1 ? old : fresh);
      }});
      await manager.getToken();
      const call = createAuthInterceptor(manager)(async () => {
        attempts++; started.resolve(); return failure.promise;
      })({ header: new Headers() });
      const rejected = assert.rejects(call, error => error === unauthorized);
      await started.promise;
      if (reset === "logout") await manager.logout(); else manager.clear();
      assert.equal(await manager.getToken(), fresh);
      failure.reject(unauthorized);
      await rejected;
      assert.equal(attempts, 1);
      assert.equal(fetches, 2);
      assert.equal(await manager.getToken(), fresh);
    });
  }
});

test("logout during refresh prevents the original RPC from being replayed", async () => {
  const old = token("old-user"), fresh = token("new-user");
  const pending = deferred(), started = deferred();
  const unauthorized = new ConnectError("expired", Code.Unauthenticated);
  let fetches = 0, attempts = 0;
  const manager = new AuthTokenManager({ fetch: async url => {
    if (url === "/auth/logout") return new Response(null, { status: 204 });
    if (++fetches === 1) return response(old);
    if (fetches === 2) { started.resolve(); return pending.promise; }
    return response(fresh);
  }});
  await manager.getToken();
  const call = createAuthInterceptor(manager)(async () => { attempts++; throw unauthorized; })({ header: new Headers() });
  const rejected = assert.rejects(call, error => error === unauthorized);
  await started.promise;
  await manager.logout();
  pending.resolve(response(old));
  await rejected;
  assert.equal(attempts, 1);
  assert.equal(await manager.getToken(), fresh);
  assert.equal(fetches, 3);
});

test("public RPCs can proceed anonymously when the session endpoint returns 401", async () => {
  const manager = new AuthTokenManager({ fetch: async () => new Response(null, { status: 401 }) });
  let calls = 0;
  const result = await createAuthInterceptor(manager)(async req => {
    calls++;
    assert.equal(req.header.get("Authorization"), null);
    return { message: "public" };
  })({ header: new Headers() });
  assert.equal(result.message, "public");
  assert.equal(calls, 1);
});
