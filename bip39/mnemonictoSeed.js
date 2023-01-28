const crypto = require('crypto');
const mnemonic = "pistol scene liar animal cart thunder pen process void job regret hold"
// Implementing pbkdf2 with all its parameters
crypto.pbkdf2(mnemonic, 'mnemonic', 2048, 64,
  'sha512', (err, derivedKey) => {

    if (err) throw err;

    // Prints derivedKey
    console.log('seed: ' + derivedKey.toString('hex'));
  });
