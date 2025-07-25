# AuthenticationClient-JS

A lightweight wrapper for handling **OpenID Connect** authentication flows in both browser-based and headless environments using [`openid-client`](https://github.com/panva/node-openid-client) and [`jose`](https://github.com/panva/jose).

Supports:

* Authorization Code Flow (with PKCE)
* Client Credentials Flow
* Token Refresh
* ID/Access Token management
* Server-side token validation (with remote JWKS)

---

## Installation

```bash
npm install openid-client jose
```

Copy the `authClient` module into your project.

---

## Usage

### 1. Initialize the Client

```js
await authClient.init('https://your-issuer.com', 'client_id', 'client_secret');
```

* `client_secret` is optional (e.g., for public SPA clients)
* Must be called before any flow begins.

---

### 2. Authorization Code Flow (Browser-based)

#### a. Start the Flow

```js
const { redirectUri, state, codeVerifier } = await authClient.authorizationCodeFlow(
  'https://your-app.com/callback',
  'openid profile email',
  'https://your-api.com'
);
// Redirect the user to `redirectUri`
```

#### b. Complete the Flow

In your callback handler:

```js
await authClient.completeAuthFlow(window.location.href, state, codeVerifier);
```

---

### 3. Client Credentials Flow (Headless)

```js
await authClient.clientCredentialFlow('read:data', 'https://your-api.com');
```

---

### 4. Refresh Token

```js
await authClient.refreshToken('openid profile email', 'https://your-api.com');
```

---

### 5. Logout

```js
const logoutUrl = await authClient.logout('https://your-app.com/logged-out');
window.location.href = logoutUrl;
```

---

### 6. Token Management

```js
authClient.getAccessToken();   // string | undefined
authClient.getIdToken();       // string | undefined
authClient.getRefreshToken();  // string | undefined

authClient.getTokenSet();      // raw tokenSet
authClient.setTokenSet(ts);    // replace tokenSet
```

---

### 7. Verify Access Token (Server-side)

```js
const payload = await authClient.verifyAccessToken(accessToken, 'https://your-api.com');
```

---

### 8. Token Update Callback

```js
authClient.onTokenUpdate((tokens) => {
  // handle token updates (e.g., save to cookie or localStorage)
});
```

---

## Notes

* If you're using a Let's Encrypt cert and see TLS errors, you may need to debug certificate rejection:

  ```js
  // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // Use cautiously!
  ```
* Ensure your issuer metadata includes a valid `jwks_uri`.

---

## Exports

The module exports a default object with the following methods:

```js
{
  init,
  authorizationCodeFlow,
  clientCredentialFlow,
  onTokenUpdate,
  completeAuthFlow,
  refreshToken,
  logout,
  verifyAccessToken,
  getTokenSet,
  getRefreshToken,
  getAccessToken,
  getIdToken,
  setTokenSet
}
```
