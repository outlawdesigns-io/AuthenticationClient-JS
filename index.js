import * as client from 'openid-client';

let config, tokenSet, onUpdateCallback;

//figure out why our letsencrypt cert gets rejected
// process.env.NODE_TLS_REJECT_UNAUTHORIZED=0;

async function init(issuerUrl, clientId, clientSecret = null){
  config = await client.discovery(
    issuerUrl,
    clientId,
    clientSecret
  );
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
async function authorizationCodeToAccessToken(currentUrl, expectedState, code_verifier){
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

function onTokenUpdate(cb){
  onUpdateCallback = cb;
}

function getAccessToken(){
  return tokenSet?.access_token;
}

const authClient = {
  init:init,
  authorizationCodeFlow:authorizationCodeFlow,
  clientCredentialFlow:clientCredentialFlow,
  getAccessToken:getAccessToken,
  onTokenUpdate:onTokenUpdate,
  authorizationCodeToAccessToken:authorizationCodeToAccessToken,
  refreshToken:refreshToken,
  logout:logout
};

export default authClient;
