# lite-lamport
Lamport one-time signature scheme library.

## Installation

```bash
npm install lite-lamport
```

## Usage

### Basic

```js
const LiteLamport = require('lite-lamport');

let lamport = new LiteLamport();

// Generate private key and public key
let { privateKey, publicKey } = lamport.generateKeys();

let message = 'hello world';

// Sign message
let signature = lamport.sign(message, privateKey);

// Verify message; returns true or false
lamport.verify(message, signature, publicKey);
```

### Generate keys from from seed

```js
const LiteLamport = require('lite-lamport');

let lamport = new LiteLamport();

// Generate random secret seed
let seed = lamport.generateSeed();

// Generate private key and public key from a seed with index as second argument
let { privateKey, publicKey } = lamport.generateKeysFromSeed(seed, 0);
```

Works on Node.js and in the browser.

## License

MIT
