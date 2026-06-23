import { jwtDecode } from "jwt-decode";

type AccessTokenClaims = {
  exp?: number;
};

type TokenResponse = {
  access_token?: string;
};

type Fetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type AuthTokenManagerOptions = {
  tokenUrl?: string;
  logoutUrl?: string;
  refreshSkewMs?: number;
  credentials?: RequestCredentials;
  fetch?: Fetch;
};

export type TokenOptions = {
  forceRefresh?: boolean;
};

export type LogoutRedirectOptions = {
  location?: Pick<Location, "assign">;
};

export class AuthTokenManager {
  private readonly tokenUrl: string;
  private readonly logoutUrl: string;
  private readonly refreshSkewMs: number;
  private readonly credentials: RequestCredentials;
  private readonly fetch: Fetch;
  private token?: { value: string; expiresAtMs: number };
  private pendingToken?: Promise<string | undefined>;

  constructor(options: AuthTokenManagerOptions = {}) {
    this.tokenUrl = options.tokenUrl ?? "/auth/token";
    this.logoutUrl = options.logoutUrl ?? "/auth/logout";
    this.refreshSkewMs = options.refreshSkewMs ?? 60_000;
    this.credentials = options.credentials ?? "same-origin";
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async getToken(options: TokenOptions = {}): Promise<string | undefined> {
    if (!options.forceRefresh && this.token && !this.isExpiring(this.token.expiresAtMs)) {
      return this.token.value;
    }
    if (!options.forceRefresh && this.pendingToken) {
      return this.pendingToken;
    }

    this.pendingToken = this.fetchToken();
    try {
      return await this.pendingToken;
    } finally {
      this.pendingToken = undefined;
    }
  }

  clear() {
    this.token = undefined;
  }

  async logout() {
    this.clear();
    await this.fetch(this.logoutUrl, {
      credentials: this.credentials,
      method: "POST",
    });
  }

  logoutWithRedirect(options: LogoutRedirectOptions = {}) {
    this.clear();
    const location = options.location ?? globalThis.location;
    location.assign(this.logoutUrl);
  }

  private async fetchToken(): Promise<string | undefined> {
    const response = await this.fetch(this.tokenUrl, {
      credentials: this.credentials,
      method: "POST",
    });
    if (response.status === 401) {
      this.clear();
      return undefined;
    }
    if (!response.ok) {
      this.clear();
      throw new Error("Unable to refresh auth session.");
    }

    const body = (await response.json()) as TokenResponse;
    if (!body.access_token) {
      this.clear();
      return undefined;
    }

    this.token = {
      value: body.access_token,
      expiresAtMs: tokenExpiresAtMs(body.access_token),
    };
    return this.token.value;
  }

  private isExpiring(expiresAtMs: number): boolean {
    return Date.now() + this.refreshSkewMs >= expiresAtMs;
  }
}

function tokenExpiresAtMs(token: string): number {
  const claims = jwtDecode<AccessTokenClaims>(token);
  if (!claims.exp) {
    throw new Error("Auth token is missing an expiration.");
  }
  return claims.exp * 1000;
}
