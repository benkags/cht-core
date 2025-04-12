const rewire = require('rewire');
const chai = require('chai');
const sinon = require('sinon');
const db = require('../../../src/db');
const config = require('../../../src/config');
const dataContext = require('../../../src/services/data-context');
const { users } = require('@medic/user-management')(config, db, dataContext);
const template = require('../../../src/services/template');
const secureSettings = require('@medic/settings');
const settingsService = require('../../../src/services/settings');
const environment = require('@medic/environment');

const client = require('../../../src/openid-client-wrapper.js');

let controller;

let req;
let res;

const pathPrefix = '/' + environment.db + '/';

describe('sso controller', () => {
  const settings =  {
    oidc_provider: {
      discovery_url: 'http://discovery.url',
      client_id: 'client_id',
      clientSecret: 'client-secret'
    }
  }

  const ASConfig = {
    serverMetadata: () => ({
      supportsPKCE: () => true,
    }),
    clientMetadata: () => {return {client_id: 'id'}}
  }

  const id_token = 'token123'
    , name = 'ari'
    , preferred_username = 'ari'
    , email = 'ari@test';

  const claims = () => {
    return { name, preferred_username, email };
  }

  const init = async () => {
    sinon.stub(settingsService, 'get').returns(settings);

    sinon.stub(secureSettings, 'getCredentials').resolves('secret');
    await controller.init();
  }

  beforeEach(async () => {
    template.clear();
    controller = rewire('../../../src/controllers/sso');

    req = {
      query: {},
      body: {},
      hostname: 'xx.app.medicmobile.org',
      protocol: 'http',
      headers: {cookie: ''},
      get: function () {
        return this.hostname;
      }
    };
    res = {
      redirect: () => 'https://fake-url.com',
      send: () => {},
      status: () => ({json: () => {}}),
      json: () => {},
      cookie: () => {},
      clearCookie: () => {},
      setHeader: () => {}
    };

    sinon.stub(client, 'discovery').resolves(ASConfig);
    sinon.stub(client, 'randomPKCECodeVerifier').returns('verifier123');
    sinon.stub(client, 'calculatePKCECodeChallenge').resolves('challenge123');
    sinon.stub(client, 'buildAuthorizationUrl').returns('https://fake-url.com');
    sinon.stub(client, 'authorizationCodeGrant').resolves({ id_token, claims });
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('init', () => {
    it('should return authorization server config object', async () => {
      await init();
      const config = await controller.__get__('ASConfig');
      chai.expect(config).to.be.deep.equal(ASConfig);
    });

    it('should use settings config', async() => {
      await init();
      chai.expect(client.discovery.calledWith(new URL(settings.oidc_provider.discovery_url), settings.oidc_provider.client_id, 'secret')).to.be.true;
    })

    it('should throw an error if no secret is found', async () => {
      sinon.stub(settingsService, 'get').returns(settings);
      sinon.stub(secureSettings, 'getCredentials').resolves(null);

      try {
        await controller.init();
        chai.expect.fail('Expected error to be thrown');
      } catch (err) {
        chai.expect(err.message).to.equal('No OIDC client secret \'oidc:client-secret\' configured.');
      }
    });

    it('should not return server config if SSO is not enabled.', async () => {
      sinon.stub(settingsService, 'get').returns({});
      sinon.stub(secureSettings, 'getCredentials').resolves('secret');
      const config = await controller.init();
      chai.expect(config).to.be.undefined;
    });
  });

  describe('networkCallRetry', () => {
    it('should retry 3 times', async () => {
      const fn = sinon.fake.throws("Error");
      try {
        await controller.__get__('networkCallRetry')(fn, 3);
        chai.expect.fail('Error');
      } catch (err) {
        chai.expect(fn.calledThrice).to.be.true;
      }
    });
  });

  describe('getAuthorizationUrl', () => {
    it('should return the authorization URL', async () => {
      await init();
      const url = await controller.__get__('getAuthorizationUrl')(ASConfig, 'http://localhost/medic/oidc/get_token');
      chai.expect(url).to.equal('https://fake-url.com');
    });

    it('should set PKCE paramemers', async () => {
      await init();
      const redirect = 'http://localhost/medic/oidc/get_token';
      const expectedParams = {
        redirect_uri: redirect,
        scope: 'openid',
        code_challenge_method: 'S256',
        code_challenge: 'challenge123'
      };
      await controller.__get__('getAuthorizationUrl')(ASConfig, redirect);
      chai.expect(client.buildAuthorizationUrl.calledWith(ASConfig, expectedParams)).to.be.true;
    });
  });

  describe('getToken', async () => {
    it('should return a token', async () => {
      await init();
      req.query.code = 'code123';
      req.query.state = 'state123';
      req.cookies = { verifier: 'verifier123' };

      const token = await controller.__get__('getIdToken')(ASConfig, 'http://current_url/');
      chai.expect(token).to.deep.equal({
        id_token,
        user: {
          name,
          username: preferred_username,
          email
        }
      });
    });

    it('should set PKCE paramemers', async () => {
      await init();
      const expectedParams = {
        idTokenExpected: true,
        pkceCodeVerifier: 'random'
      };
      controller.__set__('code_verifier', 'random');
      await controller.__get__('getIdToken')(ASConfig, 'http://current_url/');
      chai.expect(client.authorizationCodeGrant.calledWith(ASConfig, 'http://current_url/', expectedParams)).to.be.true;
    });
  });
});
