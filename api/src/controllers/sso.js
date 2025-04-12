const { createHmac } = require('crypto');

const config = require('../config');
const db = require('../db');
const dataContext = require('../services/data-context');
const { users } = require('@medic/user-management')(config, db, dataContext);
const logger = require('@medic/logger');
const secureSettings = require('@medic/settings');
const environment = require('@medic/environment');
const request = require('@medic/couch-request');

const client = require('../openid-client-wrapper');
const { setCookies, sendLoginErrorResponse } = require('./login');
const settingsService = require('../services/settings');
const { setTimeout } = require('later');

const OIDC_CLIENT_SECRET_KEY = "oidc:client-secret";

let ASConfig;
let code_verifier;

const networkCallRetry = async (call, retryCount = 3) => {
  try {
    return await call();
  } catch (err) {
    if (retryCount == 1) {
      throw err;
    }
    logger.debug(`Retrying ${call}.}`)
    new Promise(resolve => setTimeout(resolve, 10));
    return await networkCallRetry(call, --retryCount);
  }
}

const init = async () => {
  const settings = await settingsService.get()
  if(!settings.oidc_provider) {
    logger.info('Authorization server config settings not provided.');
    return;
  }

  const clientSecret = await secureSettings.getCredentials(OIDC_CLIENT_SECRET_KEY);
  if(!clientSecret) {
    const err = `No OIDC client secret '${OIDC_CLIENT_SECRET_KEY}' configured.`
    logger.error(err)
    throw new Error(err);
  }

  try {
    ASConfig = await networkCallRetry(
      () => client.discovery(new URL(settings.oidc_provider.discovery_url), settings.oidc_provider.client_id, clientSecret),
      3
    )
  } catch (e) {
    logger.error(e)
    const err = 'The SSO provider is unreachable.';
    throw { status: 503, error: err };
  }

  logger.info('Authorization server config auth config loaded successfully.');

  return ASConfig;
}

const getAuthorizationUrl = async (serverConfig, redirectUrl) => {
  code_verifier = client.randomPKCECodeVerifier();

  const code_challenge_method = 'S256';
  const code_challenge = await client.calculatePKCECodeChallenge(code_verifier);

  let parameters = {
    redirect_uri: redirectUrl,
    scope: 'openid'
  }

  if(serverConfig?.serverMetadata()?.supportsPKCE()) {
    parameters = { ...parameters, ...{ code_challenge_method, code_challenge } }
  }

  return client.buildAuthorizationUrl(serverConfig, parameters);
}

const getIdToken = async (serverConfig, currentUrl) => {
  let params = {};

  if(serverConfig?.serverMetadata()?.supportsPKCE()) {
    params = {
      idTokenExpected: true,
      pkceCodeVerifier: code_verifier
    }
  }

  const tokens = await client.authorizationCodeGrant(ASConfig, currentUrl, params);

  const { id_token } = tokens;
  const { name, preferred_username, email } = tokens.claims();

  return {
    id_token,
    user: {
      name,
      username: preferred_username,
      email
    }
  }
}

const makeCookie = (username, salt, secret, authTimeout) => {
  // an adaptation of https://medium.com/@eiri/couchdb-cookie-authentication-6dd0af6817da
  const expiry = Math.floor(Date.now() / 1000) + authTimeout;

  const msg = `${username}:${expiry.toString(16).toUpperCase()}`;

  const key = `${secret}${salt}`;

  const hmac = createHmac('sha1', key).update(msg).digest();

  const control = new Uint8Array(hmac);

  const cookie = Buffer.concat([
    Buffer.from(msg),
    Buffer.from(':'),
    Buffer.from(control)
  ]).toString('base64')

  return cookie.replace(/=+$/, "").replaceAll("/", "_").replaceAll("+", "-");
}

const getSession = async cookie => {
  const sessionRes = await request.get({
    url: new URL('/_session', environment.serverUrlNoAuth).toString(),
    json: true,
    simple: false,
    headers: {
      'Cookie': cookie
    }
  });

  if(!sessionRes || sessionRes.status !== 200) {
    logger.error(`Could not get session. Status: ${sessionRes.status} - ${sessionRes.body}`)
    throw { error: 'Could not log in', status: 401 }
  }

  return sessionRes;
};

const getCouchConfigUrl = (nodeName = '_local') => {
  const couchUrl = process.env.COUCH_URL;
  const serverUrl =  couchUrl && couchUrl.slice(0, couchUrl.lastIndexOf('/'));

  if (!serverUrl) {
    logger.error(`Failed to find the CouchDB server from env COUCH_URL: ${COUCH_URL}`);
    throw {status: 400, error: 'An error occured when logging in.'}
  }

  return `${serverUrl}/_node/${nodeName}/_config`;
};

const getCookie = async (username) => {
  const secret = await request.get({
    url: `${getCouchConfigUrl()}/couch_httpd_auth/secret`,
    json: true
  });

  if(!secret) {
    logger.error('CouchDB Secret has not been set.');
    throw { status: 400, error: 'An error occurred when logging in.' };
  }

  const userDoc = await users.getUserDoc(username);

  const authTimeout = await request.get({
    url: `${getCouchConfigUrl()}/couch_httpd_auth/timeout`,
    json: true
  });

  const cookie = makeCookie(username, userDoc.salt, secret, authTimeout);

  return `AuthSession=${cookie}`;
};

const login = async (req, res) => {
  req.body = { locale: 'en' };
  const currentUrl =  new URL(`${req.protocol}://${req.get('host')}${req.originalUrl}`);
  try {
    const auth = await getIdToken(ASConfig, currentUrl);
    const cookie = await getCookie(auth.user.username);
    const sessionRes = await getSession(cookie);
    const redirectUrl = await setCookies(req, res, sessionRes, cookie);
    res.redirect(redirectUrl);
  } catch (e) {
    return sendLoginErrorResponse(e, res);
  }
};

const authorize = async (req, res) => {
  const redirectUrl = new URL(
    `/${environment.db}/oidc/get_token`,
    `${req.protocol}://${req.get('host')}`
  ).toString();
  const authUrl = await getAuthorizationUrl(ASConfig, redirectUrl);
  res.redirect(301, authUrl.href);
}

module.exports = {
  init,
  authorize,
  login
}
 