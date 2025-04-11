import axios from 'axios';

let _instance = null;
let _authToken = null;
let _baseUrl = null;

function _createInstance(baseURL){
  const client = axios.create({ baseURL:baseURL });
  if(_authToken){
    client.defaults.headers.common['auth_token'] = _authToken;
  }
  return client;
}
function _setAuthToken(token){
  _authToken = token;
  if(_instance){
    _instance.defaults.headers.common['auth_token'] = _authToken;
  }
}
async function _authenticate(username,password){
  if(!_instance) throw new Error('API client not instantiated with baseURL.');
  const headers = {'request_token':username, 'password':password};
  const response = await _instance.get('/authenticate',{headers:headers});
  if(response.status == 200 && !response.data.error){
    _setAuthToken(response.data.token);
    return response.data.token;
  }
  throw response.data;
}
async function _isTokenValid(auth_token){
  if (!_instance) throw new Error('API client not instantiated with baseURL.');
  _setAuthToken(auth_token);
  const response = await _instance.get('/verify');
  if(response.status == 200 && !response.data.error){
    return true;
  }else if(response.status == 200 && response.data.error && response.data.error.includes('Invalid Token')){
    return false;
  }
  throw response.data;
}

const apiClient = {
  init(baseURL = process.env.OD_ACCOUNTS_BASE_URL){
    if(_baseUrl && baseURL !== _baseUrl){
      throw new Error(`API client already initialized with ${_baseUrl}`);
    }
    if(!baseURL){
      throw new Error('API client cannot be initialized without baseURL');
    }
    if(!_instance){
      _baseUrl = baseURL;
      _instance = _createInstance(_baseUrl);
    }
  },
  async authenticate(username = process.env.OD_ACCOUNTS_USER,password = process.env.OD_ACCOUNTS_PASS){
    if(!username || !password){
      throw new Error('Cannot authenticate without credentials.');
    }
    return await _authenticate(username,password);
  },
  async checkToken(auth_token,username = process.env.OD_ACCOUNTS_USER,password = process.env.OD_ACCOUNTS_PASS){
    const validToken = await _isTokenValid(auth_token);
    if(!username || !password){
      throw new Error('Cannot authenticate without credentials.');
    }
    if(!validToken){
      return await _authenticate(username,password);
    }
    return auth_token;
  },
  getAuthToken(){
    return _authToken;
  },
  get instance(){
    if(!_instance){
      throw new Error('API client not initialized. Call apiClient.init(baseURL) first.');
    }
    return _instance;
  }
}

export default apiClient;
