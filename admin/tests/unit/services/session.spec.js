describe('Session service', function() {

  'use strict';

  let service;
  let ipCookie;
  let ipCookieRemove;
  let location;
  let pushStateStub;
  let $httpBackend;
  let Location;

  beforeEach(function () {
    module('adminApp');
    ipCookie = sinon.stub();
    ipCookieRemove = sinon.stub();
    ipCookie.remove = ipCookieRemove;
    pushStateStub = sinon.stub();
    Location = {};
    location = {};
    module(function ($provide) {
      $provide.factory('ipCookie', function() {
        return ipCookie;
      });
      $provide.value('Location', Location);
      $provide.factory('$window', function() {
        return {
          angular: { callbacks: [] },
          history: { pushState: pushStateStub },
          location: location,
        };
      });
    });
    inject(function(_Session_, _$httpBackend_) {
      service = _Session_;
      $httpBackend = _$httpBackend_;
    });
  });

  afterEach(function() {
    KarmaUtils.restore(ipCookie, ipCookieRemove);
  });

  it('gets the user context', function(done) {
    const expected = { name: 'bryan' };
    ipCookie.returns(expected);
    const actual = service.userCtx();
    chai.expect(actual).to.deep.equal(expected);
    chai.expect(ipCookie.args[0][0]).to.equal('userCtx');
    done();
  });

  it('logs out', function(done) {
    const expected = { name: 'adam' };
    ipCookie.returns(expected);
    location.href = 'CURRENT_URL';
    Location.dbName = 'DB_NAME';
    $httpBackend
      .expect('DELETE', '/_session')
      .respond(200);
    service.logout();
    $httpBackend.flush();
    chai.expect(location.href).to.equal(`/DB_NAME/login?redirect=CURRENT_URL&username=${expected.name}`);
    chai.expect(ipCookieRemove.args[0][0]).to.equal('userCtx');
    chai.expect(pushStateStub.calledOnce).to.be.true;
    chai.expect(pushStateStub.args[0]).to.have.members([ null, null, '/' ]);
    done();
  });

  it('logs out if no user context', function(done) {
    ipCookie.returns({});
    location.href = 'CURRENT_URL';
    Location.dbName = 'DB_NAME';
    $httpBackend
      .expect('DELETE', '/_session')
      .respond(200);
    service.checkCurrentSession();
    $httpBackend.flush();
    chai.expect(location.href).to.equal('/DB_NAME/login?redirect=CURRENT_URL');
    chai.expect(ipCookieRemove.args[0][0]).to.equal('userCtx');
    chai.expect(pushStateStub.calledOnce).to.be.true;
    chai.expect(pushStateStub.args[0]).to.have.members([ null, null, '/' ]);
    done();
  });

  it('cookie gets deleted when session expires', function(done) {
    ipCookie.returns({ name: 'bryan' });
    Location.dbName = 'DB_NAME';
    $httpBackend
      .expect('GET', '/_session')
      .respond(401);
    service.checkCurrentSession();
    $httpBackend.flush();
    chai.expect(ipCookieRemove.args[0][0]).to.equal('userCtx');
    done();
  });

  it('does not log out if server not found', function(done) {
    ipCookie.returns({ name: 'bryan' });
    $httpBackend
      .expect('GET', '/_session')
      .respond(0);
    service.checkCurrentSession();
    $httpBackend.flush();
    chai.expect(ipCookieRemove.callCount).to.equal(0);
    chai.expect(pushStateStub.notCalled).to.be.true;
    done();
  });

  it('logs out if remote userCtx inconsistent', function(done) {
    const expected = { name: 'adam' };
    ipCookie.returns(expected);
    location.href = 'CURRENT_URL';
    Location.dbName = 'DB_NAME';
    $httpBackend
      .expect('GET', '/_session')
      .respond(200, { data: { userCtx: { name: 'jimmy' } } });
    $httpBackend
      .expect('DELETE', '/_session')
      .respond(200);
    service.checkCurrentSession();
    $httpBackend.flush();
    chai.expect(location.href).to.equal(`/DB_NAME/login?redirect=CURRENT_URL&username=${expected.name}`);
    chai.expect(ipCookieRemove.args[0][0]).to.equal('userCtx');
    chai.expect(pushStateStub.calledOnce).to.be.true;
    chai.expect(pushStateStub.args[0]).to.have.members([ null, null, '/' ]);
    done();
  });

  it('does not log out if remote userCtx consistent', function(done) {
    ipCookie.returns({ name: 'bryan' });
    $httpBackend
      .expect('GET', '/_session')
      .respond(200, { userCtx: { name: 'bryan' } });
    service.checkCurrentSession();
    $httpBackend.flush();
    chai.expect(ipCookieRemove.callCount).to.equal(0);
    chai.expect(pushStateStub.notCalled).to.be.true;
    done();
  });

  describe('isAdmin function', function() {

    it('returns false if not logged in', function(done) {
      ipCookie.returns({});
      const actual = service.isAdmin();
      chai.expect(actual).to.equal(false);
      done();
    });

    it('returns true for _admin', function(done) {
      ipCookie.returns({ roles: [ '_admin' ] });
      const actual = service.isAdmin();
      chai.expect(actual).to.equal(true);
      done();
    });

    it('returns false for national_admin', function(done) {
      ipCookie.returns({ roles: [ 'national_admin', 'some_other_role' ] });
      const actual = service.isAdmin();
      chai.expect(actual).to.equal(false);
      done();
    });

    it('returns false for everyone else', function(done) {
      ipCookie.returns({ roles: [ 'district_admin', 'some_other_role' ] });
      const actual = service.isAdmin();
      chai.expect(actual).to.equal(false);
      done();
    });

  });
});
