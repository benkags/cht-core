const utils = require('@utils');
const chai = require('chai');
const sinon = require('sinon');
const uuid = require('uuid').v4;

describe('SSO API Integration Tests', () => {
  const mockOidcProvider = {
    discovery_url: 'https://auth.example.com/.well-known/openid-configuration',
    client_id: 'mock-client-id',
    client_secret: 'mock-client-secret',
  };

  before(async () => {
    // Mock OIDC provider settings
    await utils.updateSettings({
      oidc_provider: mockOidcProvider,
    }, {
      ignoreReload: true,
    });
  });

  after(async () => {
    // Revert settings after tests
    await utils.revertSettings(true);
  });

  describe('GET /api/v1/login/oidc', () => {
    it('should redirect to the OIDC provider authorization URL', async () => {
      const response = await utils.request({
        path: '/api/v1/login/oidc',
        method: 'GET',
        resolveWithFullResponse: true,
        redirect: 'manual',
      });

      chai.expect(response.status).to.equal(301);
      chai.expect(response.headers.location).to.include(mockOidcProvider.discovery_url);
    });

    it('should return an error if OIDC provider settings are missing', async () => {
      await utils.updateSettings({ oidc_provider: null });

      try {
        await utils.request({
          path: '/api/v1/login/oidc',
          method: 'GET',
        });
        chai.assert.fail('Expected error was not thrown');
      } catch (err) {
        chai.expect(err.status).to.equal(500);
        chai.expect(err.body.error).to.include('Authorization server config settings not provided.');
      }
    });
  });

  describe('GET /api/v1/oidc/authorize', () => {
    it('should redirect to the OIDC provider authorization URL', async () => {
      const response = await utils.request({
        path: '/api/v1/oidc/authorize',
        method: 'GET',
        resolveWithFullResponse: true,
        redirect: 'manual',
      });

      chai.expect(response.status).to.equal(301);
      chai.expect(response.headers.location).to.include(mockOidcProvider.discovery_url);
    });

    it('should return an error if the authorization URL cannot be generated', async () => {
      sinon.stub(utils, 'request').rejects(new Error('Failed to generate authorization URL'));

      try {
        await utils.request({
          path: '/api/v1/oidc/authorize',
          method: 'GET',
        });
        chai.assert.fail('Expected error was not thrown');
      } catch (err) {
        chai.expect(err.message).to.include('Failed to generate authorization URL.');
      } finally {
        sinon.restore();
      }
    });
  });

  describe('GET /api/v1/oidc/get_token', () => {
    it('should log in the user after successful token exchange', async () => {
      const mockUser = {
        username: 'testuser',
        password: 'password123',
      };

      // Simulate a successful token exchange
      const response = await utils.request({
        path: '/api/v1/oidc/get_token',
        method: 'GET',
        qs: {
          code: 'mock-auth-code',
          state: uuid(),
        },
        resolveWithFullResponse: true,
        redirect: 'manual',
      });

      chai.expect(response.status).to.equal(302);
      chai.expect(response.headers.location).to.equal('/');
      chai.expect(response.headers.getSetCookie()).to.be.an('array');
      chai.expect(response.headers.getSetCookie().find(cookie => cookie.startsWith('AuthSession'))).to.be.ok;
    });

    it('should return an error if the token exchange fails', async () => {
      try {
        await utils.request({
          path: '/api/v1/oidc/get_token',
          method: 'GET',
          qs: {
            code: 'invalid-auth-code',
            state: uuid(),
          },
        });
        chai.assert.fail('Expected error was not thrown');
      } catch (err) {
        chai.expect(err.status).to.equal(400);
        chai.expect(err.body.error).to.include('Invalid authorization code');
      }
    });

    it('should return an error if the user is not found', async () => {
      sinon.stub(utils, 'request').resolves({
        id_token: 'mock-id-token',
        user: null,
      });

      try {
        await utils.request({
          path: '/api/v1/oidc/get_token',
          method: 'GET',
          qs: {
            code: 'mock-auth-code',
            state: uuid(),
          },
        });
        chai.assert.fail('Expected error was not thrown');
      } catch (err) {
        chai.expect(err.status).to.equal(401);
        chai.expect(err.body.error).to.include('Invalid. Could not login using SSO.');
      } finally {
        sinon.restore();
      }
    });
  });
});