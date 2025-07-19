import * as client from 'openid-client';
import * as jose from 'jose';

let config, tokenSet, onUpdateCallback, issuerUrl, jwks;

//figure out why our letsencrypt cert gets rejected
// process.env.NODE_TLS_REJECT_UNAUTHORIZED=0;

async function init(issuerUrlStr, clientId, clientSecret = null){
  issuerUrl = new URL(issuerUrlStr);
  config = await client.discovery(issuerUrl,clientId,clientSecret);
  const res = await fetch(issuerUrl);
  const metadata = await res.json();
  const jwksUri = metadata.jwks_uri;
  jwks = jose.createRemoteJWKSet(new URL(jwksUri));
}
//user interactive sign-in
async function authorizationCodeFlow(redirectUri, scope) {
  if(!config){
    throw new Error('call: init(issuerUrl, clientId, [secret])');
  }
  let codeVerifier = client.randomPKCECodeVerifier();
  let codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  let state = client.randomState();
  let parameters = {
    redirectUri,
    scope,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: state
  }
  let redirectTo = client.buildAuthorizationUrl(config,parameters);
  return {
    redirectUri: redirectTo.href,
    state: state,
    codeVerifier: codeVerifier
  }
}
async function completeAuthFlow(currentUrl, expectedState, code_verifier){
  if(!config){
    throw new Error('call: init(issuerUrl, clientId, redirectUri)');
  }
  tokenSet = await client.authorizationCodeGrant(config,currentUrl,{pkceCodeVerifier: code_verifier, expectedState: expectedState});
}
async function logout(postLogoutUri, idToken){
  let redirectTo = client.buildEndSessionUrl(config,{
    post_logout_redirect_uri: postLogoutUri,
    id_token_hint: idToken
  });
  return redirectTo.href
}
//Headless App Authentication
async function clientCredentialFlow(scope, resource){
  tokenSet = await client.clientCredentialsGrant(config, { scope, resource });
}
async function refreshToken(refreshToken,scope,resource){
  tokenSet = await client.refreshTokenGrant(config,refreshToken,{
    scope,
    resource
  });
}
//Server-side token validation
async function verifyAccessToken(access_token,audience){
  let result;
  try{
    result = await jose.jwtVerify(access_token,jwks,{
      issuer: issuerUrl.origin,
      audience: audience
    });
  }catch(err){
    throw err;
  }
  return result.payload;
}

function onTokenUpdate(cb){
  onUpdateCallback = cb;
}

function getAccessToken(){
  return tokenSet?.access_token;
}
function getIdToken(){
  return tokenSet?.id_token;
}

const authClient = {
  init:init,
  authorizationCodeFlow:authorizationCodeFlow,
  clientCredentialFlow:clientCredentialFlow,
  getAccessToken:getAccessToken,
  getIdToken:getIdToken,
  onTokenUpdate:onTokenUpdate,
  completeAuthFlow:completeAuthFlow,
  refreshToken:refreshToken,
  logout:logout,
  verifyAccessToken:verifyAccessToken,

};

export default authClient;
