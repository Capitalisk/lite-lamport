const assert = require('assert');
const LiteLamport = require('../index');
const hash = require('hash.js');

describe('Unit tests', async () => {

  let lamport;

  beforeEach(async () => {
    lamport = new LiteLamport({
      keyFormat: 'base64',
      signatureFormat: 'base64',
      seedEncoding: 'hex',
      hashEncoding: 'base64'
    });
  });

  describe('Generate keys', async () => {
    it('should return a valid private key and public key pair', async () => {
      let { privateKey, publicKey } = lamport.generateKeys();
      let rawPrivateKey = lamport.decodeKey(privateKey);
      let rawPublicKey = lamport.decodeKey(publicKey);
      assert.equal(rawPrivateKey.length, 264);
      assert.equal(rawPublicKey.length, 264);
    });
  });

  describe('Generate keys from seed', async () => {
    it('should return a valid private key and public key pair from seed', async () => {
      let seed = lamport.generateSeed();
      let { privateKey, publicKey } = lamport.generateKeysFromSeed(seed, 0);
      let rawPrivateKey = lamport.decodeKey(privateKey);
      let rawPublicKey = lamport.decodeKey(publicKey);
      assert.equal(rawPrivateKey.length, 264);
      assert.equal(rawPublicKey.length, 264);
    });
  });

  describe('Sign', async () => {
    let privateKey;
    let publicKey;

    beforeEach(async () => {
      let keyPair = lamport.generateKeys();
      privateKey = keyPair.privateKey;
      publicKey = keyPair.publicKey;
    });

    it('should return signature as a string made up of no more than 264 entries', async () => {
      let signature = lamport.sign('test message', privateKey);
      let rawSignature = lamport.decodeSignature(signature);
      assert.equal(rawSignature.length <= 264, true);
    });
  });

  describe('Verify', async () => {
    let privateKey;
    let publicKey;

    beforeEach(async () => {
      let keyPair = lamport.generateKeys();
      privateKey = keyPair.privateKey;
      publicKey = keyPair.publicKey;
    });

    it('should return true if signature is valid', async () => {
      let message = 'hello world';
      let signature = lamport.sign(message, privateKey);
      let verified = lamport.verify(message, signature, publicKey);
      assert.equal(verified, true);
    });

    it('should return false if signature is not valid', async () => {
      let message = 'hello world';
      let signature = lamport.sign(message, privateKey);
      let badSignature = lamport.sign('different message', privateKey);
      let verified = lamport.verify(message, badSignature, publicKey);
      assert.equal(verified, false);
    });
  });
});
