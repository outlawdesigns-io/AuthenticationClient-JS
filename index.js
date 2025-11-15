import * as client from 'openid-client';
import * as jose from 'jose';

let config, tokenSet, onUpdateCallback, issuerUrl, jwks;

//figure out why our letsencrypt cert gets rejected
// process.env.NODE_TLS_REJECT_UNAUTHORIZED=0;

async function init(issuerUrlStr, clientId, clientSecret = null){
  console.log('custom init hit!');
  issuerUrl = new URL(issuerUrlStr);
  config = await client.discovery(issuerUrl,clientId,clientSecret);
  const res = await fetch(issuerUrl);
  const metadata = await res.json();
  const jwksUri = metadata.jwks_uri;
  jwks = jose.createRemoteJWKSet(new URL(jwksUri));
}
//user interactive sign-in
async function authorizationCodeFlow(redirectUri, scope, resources = []) {
  if(!config){
    throw new Error('call: init(issuerUrl, clientId, [secret])');
  }
  let codeVerifier = client.randomPKCECodeVerifier();
  let codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  let state = client.randomState();
  let parameters = new URLSearchParams({
    redirect_uri:redirectUri,
    scope,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: state
  });
  if(resources.length){
    resources.map(r => parameters.append('audience', r));
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
    throw new Error('call: init(issuerUrl, clientId, [secret])');
  }
  tokenSet = await client.authorizationCodeGrant(config,currentUrl,{pkceCodeVerifier: code_verifier, expectedState: expectedState});
}
async function logout(postLogoutUri){
  if(!tokenSet.id_token){
    throw new Error('Unable to logout. No id_token available');
  }
  let redirectTo = client.buildEndSessionUrl(config,{
    post_logout_redirect_uri: postLogoutUri,
    id_token_hint: tokenSet.id_token
  });
  return redirectTo.href
}
//Headless App Authentication
async function clientCredentialFlow(scope, resources = []){
  let parameters = new URLSearchParams({ scope });
  if(resources.length){
    resources.map(r => parameters.append('audience',r));
  }
  tokenSet = await client.clientCredentialsGrant(config, parameters);
}
async function refreshToken(scope,resources = []){
  if(!tokenSet.refresh_token){
    throw new Error('No refresh_token available');
  }
  let parameters = new URLSearchParams({ scope });
  if(resources.length){
    resources.map(r => parameters.append('audience',r));
  }
  tokenSet = await client.refreshTokenGrant(config,tokenSet.refresh_token,parameters);
}
//Server-side token validation
async function verifyAccessToken(access_token,audience = []){
  let result;
  let parameters = new URLSearchParams({issuer: issuerUrl.origin});
  if(audience.length){
    audience.map(r => parameters.append('audience',r));
  }
  try{
    result = await jose.jwtVerify(access_token,jwks,parameters);
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
function getRefreshToken(){
  return tokenSet?.refresh_token;
}
function setTokenSet(newTokenSet){
  tokenSet = newTokenSet;
}
function getTokenSet(){
  return tokenSet;
}

const authClient = {
  init:init,
  authorizationCodeFlow:authorizationCodeFlow,
  clientCredentialFlow:clientCredentialFlow,
  onTokenUpdate:onTokenUpdate,
  completeAuthFlow:completeAuthFlow,
  refreshToken:refreshToken,
  logout:logout,
  verifyAccessToken:verifyAccessToken,
  getTokenSet:getTokenSet,
  getRefreshToken:getRefreshToken,
  getAccessToken:getAccessToken,
  getIdToken:getIdToken,
  setTokenSet:setTokenSet
};

export default authClient;
