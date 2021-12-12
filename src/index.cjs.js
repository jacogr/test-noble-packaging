const { blake2b } = require('@noble/hashes/lib/blake2b');
const { getPublicKey } = require('@noble/secp256k1');

console.log('blake2b', blake2b(new Uint8Array([1, 2, 3, 4])));
console.log('getPublicKey', getPublicKey(BigInt(0x01020304)));
