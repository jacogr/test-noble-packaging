var $gLqf4$noblehasheslibblake2b = require("@noble/hashes/lib/blake2b");
var $gLqf4$noblesecp256k1 = require("@noble/secp256k1");



console.log('blake2b', $gLqf4$noblehasheslibblake2b.blake2b(new Uint8Array([
    1,
    2,
    3,
    4
])));
console.log('getPublicKey', $gLqf4$noblesecp256k1.getPublicKey(BigInt(16909060)));


//# sourceMappingURL=parcel.js.map
