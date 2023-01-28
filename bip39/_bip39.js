const bip39 = require('bip39')

const mnemonics = bip39.generateMnemonic(256)

console.log(mnemonics)

const seed = bip39.mnemonicToSeedSync(mnemonics)

console.log("seed: " + seed.toString('hex'))