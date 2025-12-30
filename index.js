const randomBytes = require('randombytes');
const sha256 = require('./sha256');
const hmacSha256 = require('./hmac-sha256');

const CHECKSUM_BYTE_SIZE = 1;
const KEY_SIG_ENTRY_COUNT = 264;
const HASH_ELEMENT_BYTE_SIZE = 32;
const SEED_BYTE_SIZE = 32;

class LiteLamport {
  constructor(options) {
    options = options || {};
    this.keyFormat = options.keyFormat || 'base64';
    this.signatureFormat = options.signatureFormat || 'base64';
    this.hashEncoding = options.hashEncoding || 'base64';
    this.seedEncoding = options.seedEncoding || 'base64';

    this.sha256 = sha256;
    this.hmacSha256 = hmacSha256;

    if (this.keyFormat === 'object') {
      this.encodeKey = (rawKey) => {
        return rawKey;
      };
      this.decodeKey = (encodedkey) => {
        this._validateRawKeyFormat(encodedkey);
        return encodedkey;
      };
    } else if (this.keyFormat === 'json') {
      this.encodeKey = (rawKey) => {
        return JSON.stringify(rawKey);
      };
      this.decodeKey = (encodedKey) => {
        let decodedKey = JSON.parse(encodedKey);
        this._validateRawKeyFormat(decodedKey);
        return decodedKey;
      };
    } else if (this.keyFormat === 'buffer') {
      this.encodeKey = (rawKey) => {
        return this._encodeKeyToBuffer(rawKey);
      };
      this.decodeKey = (encodedKey) => {
        return this._decodeKeyFromBuffer(encodedKey);
      };
    } else {
      this.encodeKey = (rawKey) => {
        return this._encodeKeyToBuffer(rawKey).toString(this.keyFormat);
      };
      this.decodeKey = (encodedKey) => {
        let keyBuffer = Buffer.from(encodedKey, this.keyFormat);
        return this._decodeKeyFromBuffer(keyBuffer);
      };
    }

    if (this.signatureFormat === 'object') {
      this.encodeSignature = (rawSignature) => {
        return rawSignature;
      };
      this.decodeSignature = (encodedSignature) => {
        this._validateRawSignatureFormat(encodedSignature);
        return [...encodedSignature];
      };
    } else if (this.signatureFormat === 'json') {
      this.encodeSignature = (rawSignature) => {
        return JSON.stringify(rawSignature);
      };
      this.decodeSignature = (encodedSignature) => {
        let decodedSignature = JSON.parse(encodedSignature);
        this._validateRawSignatureFormat(decodedSignature);
        return decodedSignature;
      };
    } else if (this.signatureFormat === 'buffer') {
      this.encodeSignature = (rawSignature) => {
        return this._encodeSignatureToBuffer(rawSignature);
      };
      this.decodeSignature = (encodedSignature) => {
        return this._decodeSignatureFromBuffer(encodedSignature);
      };
    } else {
      this.encodeSignature = (rawSignature) => {
        return this._encodeSignatureToBuffer(rawSignature).toString(this.signatureFormat);
      };
      this.decodeSignature = (encodedSignature) => {
        let signatureBuffer = Buffer.from(encodedSignature, this.signatureFormat);
        return this._decodeSignatureFromBuffer(signatureBuffer);
      };
    }
  }

  generateSeed() {
    return randomBytes(SEED_BYTE_SIZE).toString(this.seedEncoding);
  }

  getRawPublicKeyFromRawPrivateKey(privateKeyRaw) {
    return privateKeyRaw.map(encodedString => this.sha256(encodedString, this.hashEncoding));
  }

  getPublicKeyFromPrivateKey(privateKey) {
    let privateKeyRaw = this.decodeKey(privateKey);
    return this.encodeKey(this.getRawPublicKeyFromRawPrivateKey(privateKeyRaw));
  }

  generateKeysFromSeed(seed, index) {
    let seedBuffer = Buffer.from(seed, this.seedEncoding);
    if (seedBuffer.byteLength < SEED_BYTE_SIZE) {
      throw new Error(
        `The specified seed encoded as ${
          this.seedEncoding
        } did not meet the minimum seed length requirement of ${
          SEED_BYTE_SIZE
        } bytes - Check that the seed encoding is correct`
      );
    }
    if (index == null) {
      index = 0;
    }
    let privateKey = this.generateRandomArrayFromSeed(KEY_SIG_ENTRY_COUNT, seed, index);
    let publicKey = this.getRawPublicKeyFromRawPrivateKey(privateKey);

    return {
      privateKey: this.encodeKey(privateKey),
      publicKey: this.encodeKey(publicKey)
    };
  }

  generateKeys() {
    let privateKey = this.generateRandomArray(KEY_SIG_ENTRY_COUNT, HASH_ELEMENT_BYTE_SIZE);
    let publicKey = this.getRawPublicKeyFromRawPrivateKey(privateKey);

    return {
      privateKey: this.encodeKey(privateKey),
      publicKey: this.encodeKey(publicKey)
    };
  }

  sign(message, privateKey) {
    let privateKeyRaw = this.decodeKey(privateKey);
    let messageHash = this.sha256(message, this.hashEncoding);
    let messageBitArray = this.convertEncodedStringToBitArray(messageHash);
    let checksum = messageBitArray.reduce((total, bit) => total + (bit ^ 1), 0);
    let checksumBuffer = Buffer.alloc(CHECKSUM_BYTE_SIZE).fill(checksum);
    let checksumBitArray = this.convertBufferToBitArray(checksumBuffer);
    for (let bit of checksumBitArray) {
      messageBitArray.push(bit);
    }
    let signature = messageBitArray
      .map((bit, index) => bit ? privateKeyRaw[index] : null)
      .filter(item => item);

    return this.encodeSignature(signature);
  }

  verify(message, signature, publicKey) {
    let signatureRaw;
    let publicKeyRaw;
    try {
      signatureRaw = this.decodeSignature(signature);
      publicKeyRaw = this.decodeKey(publicKey);
    } catch (error) {
      return false;
    }
    let invertedSignatureRaw = signatureRaw.reverse();
    let messageHash = this.sha256(message, this.hashEncoding);
    let messageBitArray = this.convertEncodedStringToBitArray(messageHash);
    let checksum = messageBitArray.reduce((total, bit) => total + (bit ^ 1), 0);
    let checksumBuffer = Buffer.alloc(CHECKSUM_BYTE_SIZE).fill(checksum);
    let checksumBitArray = this.convertBufferToBitArray(checksumBuffer);

    for (let bit of checksumBitArray) {
      messageBitArray.push(bit);
    }

    return messageBitArray.every((bit, index) => {
      if (!bit) {
        return true;
      }
      if (!invertedSignatureRaw.length) {
        return false;
      }
      let nextSignatureItem = invertedSignatureRaw.pop();
      let signatureItemHash = this.sha256(nextSignatureItem, this.hashEncoding);
      let targetPublicKeyItem = publicKeyRaw[index];
      return signatureItemHash === targetPublicKeyItem;
    });
  }

  generateRandomArray(length, elementBytes) {
    let randomArray = [];
    for (let i = 0; i < length; i++) {
      randomArray.push(randomBytes(elementBytes).toString(this.hashEncoding));
    }
    return randomArray;
  }

  generateRandomArrayFromSeed(length, seed, suffix) {
    let randomArray = [];
    for (let i = 0; i < length; i++) {
      randomArray.push(this.hmacSha256(seed, this.seedEncoding, `${suffix}-${i}`, this.hashEncoding));
    }
    return randomArray;
  }

  convertBufferToBitArray(buffer) {
    let bitArray = [];
    for (let byte of buffer) {
      for (let i = 0; i < 8; i++) {
        bitArray.push(byte >> (7 - i) & 1);
      }
    }
    return bitArray;
  }

  convertEncodedStringToBitArray(encodedString) {
    let buffer = Buffer.from(encodedString, this.hashEncoding);
    return this.convertBufferToBitArray(buffer);
  }

  _validateRawKeyFormat(key) {
    if (!Array.isArray(key)) {
      throw new Error(
        'The specified key was in an invalid format - Expected an array'
      );
    }
    if (key.length !== KEY_SIG_ENTRY_COUNT) {
      throw new Error(
        `The specified key had an invalid length - Contained ${
          key.length
        } items but expected ${
          KEY_SIG_ENTRY_COUNT
        } items`
      );
    }
    let areAllItemsValid = key.every(item => {
      if (typeof item !== 'string') {
        return false;
      }
      return Buffer.byteLength(item, this.hashEncoding) === HASH_ELEMENT_BYTE_SIZE;
    });
    if (!areAllItemsValid) {
      throw new Error(
        'The specified key contained invalid items'
      );
    }
  }

  _validateRawSignatureFormat(signature) {
    if (!Array.isArray(signature)) {
      throw new Error(
        'The specified signature was in an invalid format - Expected an array'
      );
    }
    if (signature.length > KEY_SIG_ENTRY_COUNT) {
      throw new Error(
        `The specified signature had an invalid length - Contained ${
          signature.length
        } items but expected no more than ${
          KEY_SIG_ENTRY_COUNT
        } items`
      );
    }
    let areAllItemsValid = signature.every(item => {
      if (typeof item !== 'string') {
        return false;
      }
      return Buffer.byteLength(item, this.hashEncoding) === HASH_ELEMENT_BYTE_SIZE;
    });
    if (!areAllItemsValid) {
      throw new Error(
        'The specified signature contained invalid items'
      );
    }
  }

  _encodeKeyToBuffer(rawKey) {
    let bufferArray = [];
    for (let item of rawKey) {
      bufferArray.push(Buffer.from(item, this.hashEncoding));
    }
    return Buffer.concat(bufferArray);
  }

  _decodeKeyFromBuffer(encodedKey) {
    let key = [];
    let expectedByteSize = KEY_SIG_ENTRY_COUNT * HASH_ELEMENT_BYTE_SIZE;
    if (encodedKey.byteLength !== expectedByteSize) {
      throw new Error(
        `The specified key had an invalid length - Was ${
          encodedKey.byteLength
        } but expected ${
          expectedByteSize
        } bytes`
      );
    }
    let entryCount = encodedKey.byteLength / HASH_ELEMENT_BYTE_SIZE;
    for (let i = 0; i < entryCount; i++) {
      let byteOffset = i * HASH_ELEMENT_BYTE_SIZE;
      let bufferItem = encodedKey.slice(byteOffset, byteOffset + HASH_ELEMENT_BYTE_SIZE);
      key.push(bufferItem.toString(this.hashEncoding));
    }
    return key;
  }

  _encodeSignatureToBuffer(rawSignature) {
    let bufferArray = [];
    for (let item of rawSignature) {
      bufferArray.push(Buffer.from(item, this.hashEncoding));
    }
    return Buffer.concat(bufferArray);
  }

  _decodeSignatureFromBuffer(encodedSignature) {
    let signatureArray = [];
    let maxExpectedByteSize = KEY_SIG_ENTRY_COUNT * HASH_ELEMENT_BYTE_SIZE;
    if (encodedSignature.byteLength > maxExpectedByteSize) {
      throw new Error(
        `The specified key had an invalid length - Was ${
          encodedSignature.byteLength
        } but expected no more than ${
          maxExpectedByteSize
        } bytes`
      );
    }
    if (encodedSignature.byteLength % HASH_ELEMENT_BYTE_SIZE !== 0) {
      throw new Error(
        `The specified key had an invalid length - Was ${
          encodedSignature.byteLength
        } bytes but expected it to be a multiple of ${
          HASH_ELEMENT_BYTE_SIZE
        }`
      );
    }
    let entryCount = encodedSignature.byteLength / HASH_ELEMENT_BYTE_SIZE;
    for (let i = 0; i < entryCount; i++) {
      let byteOffset = i * HASH_ELEMENT_BYTE_SIZE;
      let bufferItem = encodedSignature.slice(byteOffset, byteOffset + HASH_ELEMENT_BYTE_SIZE);
      signatureArray.push(bufferItem.toString(this.hashEncoding));
    }
    return signatureArray;
  }
}

module.exports = LiteLamport;
