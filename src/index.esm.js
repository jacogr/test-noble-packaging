import { blake2b } from '@noble/hashes/lib/blake2b';
import { getPublicKey } from '@noble/secp256k1';

console.log('blake2b', blake2b(new Uint8Array([1, 2, 3, 4])));
console.log('getPublicKey', getPublicKey(BigInt(0x01020304)));
