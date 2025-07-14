import * as client from 'openid-client';

let config, tokenSet, onUpdateCallback;

//implement logout() and refreshToken()
//figure out why our letsencrypt cert gets rejected
// process.env.NODE_TLS_REJECT_UNAUTHORIZED=0;

async function init(issuerUrl, clientId, clientSecret = null){
  config = await client.discovery(
    issuerUrl,
    clientId,
    clientSecret
    //'$2a$10$4edhPeDnuDHe8APeG6bwz.n5cJUnkNmx39Eo2j.eVGSMHGrGG5Ts2'
    //[ redirectUri ],
    //['code'], //this probably needs to be parameterized
  );
}
//user interactive sign-in
async function authorizationCodeFlow(redirectUri, scope) {
  if(!config){
    throw new Error('call: init(issuerUrl, clientId, redirectUri)');
  }
  let codeVerifier = client.randomPKCECodeVerifier();
  let codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  console.log('verifier', codeVerifier);
  //let state;
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
  // return redirectTo.href;
}

async function authorizationCodeToAccessToken(currentUrl, expectedState, code_verifier){
  if(!config){
    throw new Error('call: init(issuerUrl, clientId, redirectUri)');
  }
  tokenSet = await client.authorizationCodeGrant(config,currentUrl,{pkceCodeVerifier: code_verifier, expectedState: expectedState});
}

async function clientCredentialFlow(scope, resource){
  tokenSet = await client.clientCredentialsGrant(config, { scope, resource });
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
};

export default authClient;
