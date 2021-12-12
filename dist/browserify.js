(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BLAKE2 = exports.SIGMA = void 0;
const utils_js_1 = require("./utils.js");
// prettier-ignore
exports.SIGMA = new Uint8Array([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    // For BLAKE2b, the two extra permutations for rounds 10 and 11 are SIGMA[10..11] = SIGMA[0..1].
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
]);
class BLAKE2 extends utils_js_1.Hash {
    constructor(blockLen, outputLen, opts = {}, keyLen, saltLen, persLen) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.length = 0;
        this.pos = 0;
        this.finished = false;
        this.destroyed = false;
        (0, utils_js_1.assertNumber)(blockLen);
        (0, utils_js_1.assertNumber)(outputLen);
        (0, utils_js_1.assertNumber)(keyLen);
        if (outputLen < 0 || outputLen > keyLen)
            throw new Error('Blake2: outputLen bigger than keyLen');
        if (opts.key !== undefined && (opts.key.length < 1 || opts.key.length > keyLen))
            throw new Error(`Key should be up 1..${keyLen} byte long or undefined`);
        if (opts.salt !== undefined && opts.salt.length !== saltLen)
            throw new Error(`Salt should be ${saltLen} byte long or undefined`);
        if (opts.personalization !== undefined && opts.personalization.length !== persLen)
            throw new Error(`Personalization should be ${persLen} byte long or undefined`);
        this.buffer32 = (0, utils_js_1.u32)((this.buffer = new Uint8Array(blockLen)));
    }
    update(data) {
        if (this.destroyed)
            throw new Error('instance is destroyed');
        // Main difference with other hashes: there is flag for last block,
        // so we cannot process current block before we know that there
        // is the next one. This significantly complicates logic and reduces ability
        // to do zero-copy processing
        const { finished, blockLen, buffer, buffer32 } = this;
        if (finished)
            throw new Error('digest() was already called');
        data = (0, utils_js_1.toBytes)(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            // If buffer is full and we still have input (don't process last block, same as blake2s)
            if (this.pos === blockLen) {
                this.compress(buffer32, 0, false);
                this.pos = 0;
            }
            const take = Math.min(blockLen - this.pos, len - pos);
            const dataOffset = data.byteOffset + pos;
            // full block && aligned to 4 bytes && not last in input
            if (take === blockLen && !(dataOffset % 4) && pos + take < len) {
                const data32 = new Uint32Array(data.buffer, dataOffset, Math.floor((len - pos) / 4));
                for (let pos32 = 0; pos + blockLen < len; pos32 += buffer32.length, pos += blockLen) {
                    this.length += blockLen;
                    this.compress(data32, pos32, false);
                }
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            this.length += take;
            pos += take;
        }
        return this;
    }
    digestInto(out) {
        if (this.destroyed)
            throw new Error('instance is destroyed');
        if (!(out instanceof Uint8Array) || out.length < this.outputLen)
            throw new Error('_Blake2: Invalid output buffer');
        const { finished, pos, buffer32 } = this;
        if (finished)
            throw new Error('digest() was already called');
        this.finished = true;
        // Padding
        this.buffer.subarray(pos).fill(0);
        this.compress(buffer32, 0, true);
        const out32 = (0, utils_js_1.u32)(out);
        this.get().forEach((v, i) => (out32[i] = v));
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        const { buffer, length, finished, destroyed, outputLen, pos } = this;
        to || (to = new this.constructor({ dkLen: outputLen }));
        to.set(...this.get());
        to.length = length;
        to.finished = finished;
        to.destroyed = destroyed;
        to.outputLen = outputLen;
        to.buffer.set(buffer);
        to.pos = pos;
        return to;
    }
}
exports.BLAKE2 = BLAKE2;

},{"./utils.js":5}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.add5H = exports.add5L = exports.add4H = exports.add4L = exports.add3H = exports.add3L = exports.add = exports.rotlBL = exports.rotlBH = exports.rotlSL = exports.rotlSH = exports.rotr32L = exports.rotr32H = exports.rotrBL = exports.rotrBH = exports.rotrSL = exports.rotrSH = exports.shrSL = exports.shrSH = exports.toBig = exports.split = exports.fromBig = void 0;
const U32_MASK64 = BigInt(2 ** 32 - 1);
const _32n = BigInt(32);
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
exports.fromBig = fromBig;
function split(lst, le = false) {
    let Ah = new Uint32Array(lst.length);
    let Al = new Uint32Array(lst.length);
    for (let i = 0; i < lst.length; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
exports.split = split;
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
exports.toBig = toBig;
// for Shift in [0, 32)
const shrSH = (h, l, s) => h >>> s;
exports.shrSH = shrSH;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
exports.shrSL = shrSL;
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
exports.rotrSH = rotrSH;
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
exports.rotrSL = rotrSL;
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
exports.rotrBH = rotrBH;
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
exports.rotrBL = rotrBL;
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (h, l) => l;
exports.rotr32H = rotr32H;
const rotr32L = (h, l) => h;
exports.rotr32L = rotr32L;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
exports.rotlSH = rotlSH;
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
exports.rotlSL = rotlSL;
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
exports.rotlBH = rotlBH;
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
exports.rotlBL = rotlBL;
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
exports.add = add;
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
exports.add3L = add3L;
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
exports.add3H = add3H;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
exports.add4L = add4L;
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
exports.add4H = add4H;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
exports.add5L = add5L;
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
exports.add5H = add5H;

},{}],3:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.blake2b = void 0;
const blake2 = __importStar(require("./_blake2.js"));
const u64 = __importStar(require("./_u64.js"));
const utils_js_1 = require("./utils.js");
// Same as SHA-512 but LE
// prettier-ignore
const IV = new Uint32Array([
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19
]);
// Temporary buffer
const BUF = new Uint32Array(32);
// Mixing function G splitted in two halfs
function G1(a, b, c, d, msg, x) {
    // NOTE: V is LE here
    const Xl = msg[x], Xh = msg[x + 1]; // prettier-ignore
    let Al = BUF[2 * a], Ah = BUF[2 * a + 1]; // prettier-ignore
    let Bl = BUF[2 * b], Bh = BUF[2 * b + 1]; // prettier-ignore
    let Cl = BUF[2 * c], Ch = BUF[2 * c + 1]; // prettier-ignore
    let Dl = BUF[2 * d], Dh = BUF[2 * d + 1]; // prettier-ignore
    // v[a] = (v[a] + v[b] + x) | 0;
    let ll = u64.add3L(Al, Bl, Xl);
    Ah = u64.add3H(ll, Ah, Bh, Xh);
    Al = ll | 0;
    // v[d] = rotr(v[d] ^ v[a], 32)
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: u64.rotr32H(Dh, Dl), Dl: u64.rotr32L(Dh, Dl) });
    // v[c] = (v[c] + v[d]) | 0;
    ({ h: Ch, l: Cl } = u64.add(Ch, Cl, Dh, Dl));
    // v[b] = rotr(v[b] ^ v[c], 24)
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: u64.rotrSH(Bh, Bl, 24), Bl: u64.rotrSL(Bh, Bl, 24) });
    (BUF[2 * a] = Al), (BUF[2 * a + 1] = Ah);
    (BUF[2 * b] = Bl), (BUF[2 * b + 1] = Bh);
    (BUF[2 * c] = Cl), (BUF[2 * c + 1] = Ch);
    (BUF[2 * d] = Dl), (BUF[2 * d + 1] = Dh);
}
function G2(a, b, c, d, msg, x) {
    // NOTE: V is LE here
    const Xl = msg[x], Xh = msg[x + 1]; // prettier-ignore
    let Al = BUF[2 * a], Ah = BUF[2 * a + 1]; // prettier-ignore
    let Bl = BUF[2 * b], Bh = BUF[2 * b + 1]; // prettier-ignore
    let Cl = BUF[2 * c], Ch = BUF[2 * c + 1]; // prettier-ignore
    let Dl = BUF[2 * d], Dh = BUF[2 * d + 1]; // prettier-ignore
    // v[a] = (v[a] + v[b] + x) | 0;
    let ll = u64.add3L(Al, Bl, Xl);
    Ah = u64.add3H(ll, Ah, Bh, Xh);
    Al = ll | 0;
    // v[d] = rotr(v[d] ^ v[a], 16)
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: u64.rotrSH(Dh, Dl, 16), Dl: u64.rotrSL(Dh, Dl, 16) });
    // v[c] = (v[c] + v[d]) | 0;
    ({ h: Ch, l: Cl } = u64.add(Ch, Cl, Dh, Dl));
    // v[b] = rotr(v[b] ^ v[c], 63)
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: u64.rotrBH(Bh, Bl, 63), Bl: u64.rotrBL(Bh, Bl, 63) });
    (BUF[2 * a] = Al), (BUF[2 * a + 1] = Ah);
    (BUF[2 * b] = Bl), (BUF[2 * b + 1] = Bh);
    (BUF[2 * c] = Cl), (BUF[2 * c + 1] = Ch);
    (BUF[2 * d] = Dl), (BUF[2 * d + 1] = Dh);
}
class BLAKE2b extends blake2.BLAKE2 {
    constructor(opts = {}) {
        super(128, opts.dkLen === undefined ? 64 : opts.dkLen, opts, 64, 16, 16);
        // Same as SHA-512, but LE
        this.v0l = IV[0] | 0;
        this.v0h = IV[1] | 0;
        this.v1l = IV[2] | 0;
        this.v1h = IV[3] | 0;
        this.v2l = IV[4] | 0;
        this.v2h = IV[5] | 0;
        this.v3l = IV[6] | 0;
        this.v3h = IV[7] | 0;
        this.v4l = IV[8] | 0;
        this.v4h = IV[9] | 0;
        this.v5l = IV[10] | 0;
        this.v5h = IV[11] | 0;
        this.v6l = IV[12] | 0;
        this.v6h = IV[13] | 0;
        this.v7l = IV[14] | 0;
        this.v7h = IV[15] | 0;
        const keyLength = opts.key ? opts.key.length : 0;
        this.v0l ^= this.outputLen | (keyLength << 8) | (0x01 << 16) | (0x01 << 24);
        if (opts.salt) {
            const salt = (0, utils_js_1.u32)((0, utils_js_1.toBytes)(opts.salt));
            this.v4l ^= salt[0];
            this.v4h ^= salt[1];
            this.v5l ^= salt[2];
            this.v5h ^= salt[3];
        }
        if (opts.personalization) {
            const pers = (0, utils_js_1.u32)((0, utils_js_1.toBytes)(opts.personalization));
            this.v6l ^= pers[0];
            this.v6h ^= pers[1];
            this.v7l ^= pers[2];
            this.v7h ^= pers[3];
        }
        if (opts.key) {
            // Pad to blockLen and update
            const tmp = new Uint8Array(this.blockLen);
            tmp.set((0, utils_js_1.toBytes)(opts.key));
            this.update(tmp);
        }
    }
    // prettier-ignore
    get() {
        let { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
        return [v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h];
    }
    // prettier-ignore
    set(v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h) {
        this.v0l = v0l | 0;
        this.v0h = v0h | 0;
        this.v1l = v1l | 0;
        this.v1h = v1h | 0;
        this.v2l = v2l | 0;
        this.v2h = v2h | 0;
        this.v3l = v3l | 0;
        this.v3h = v3h | 0;
        this.v4l = v4l | 0;
        this.v4h = v4h | 0;
        this.v5l = v5l | 0;
        this.v5h = v5h | 0;
        this.v6l = v6l | 0;
        this.v6h = v6h | 0;
        this.v7l = v7l | 0;
        this.v7h = v7h | 0;
    }
    compress(msg, offset, isLast) {
        this.get().forEach((v, i) => (BUF[i] = v)); // First half from state.
        BUF.set(IV, 16); // Second half from IV.
        let { h, l } = u64.fromBig(BigInt(this.length));
        BUF[24] = IV[8] ^ l; // Low word of the offset.
        BUF[25] = IV[9] ^ h; // High word.
        // Invert all bits for last block
        if (isLast) {
            BUF[28] = ~BUF[28];
            BUF[29] = ~BUF[29];
        }
        let j = 0;
        const s = blake2.SIGMA;
        for (let i = 0; i < 12; i++) {
            G1(0, 4, 8, 12, msg, offset + 2 * s[j++]);
            G2(0, 4, 8, 12, msg, offset + 2 * s[j++]);
            G1(1, 5, 9, 13, msg, offset + 2 * s[j++]);
            G2(1, 5, 9, 13, msg, offset + 2 * s[j++]);
            G1(2, 6, 10, 14, msg, offset + 2 * s[j++]);
            G2(2, 6, 10, 14, msg, offset + 2 * s[j++]);
            G1(3, 7, 11, 15, msg, offset + 2 * s[j++]);
            G2(3, 7, 11, 15, msg, offset + 2 * s[j++]);
            G1(0, 5, 10, 15, msg, offset + 2 * s[j++]);
            G2(0, 5, 10, 15, msg, offset + 2 * s[j++]);
            G1(1, 6, 11, 12, msg, offset + 2 * s[j++]);
            G2(1, 6, 11, 12, msg, offset + 2 * s[j++]);
            G1(2, 7, 8, 13, msg, offset + 2 * s[j++]);
            G2(2, 7, 8, 13, msg, offset + 2 * s[j++]);
            G1(3, 4, 9, 14, msg, offset + 2 * s[j++]);
            G2(3, 4, 9, 14, msg, offset + 2 * s[j++]);
        }
        this.v0l ^= BUF[0] ^ BUF[16];
        this.v0h ^= BUF[1] ^ BUF[17];
        this.v1l ^= BUF[2] ^ BUF[18];
        this.v1h ^= BUF[3] ^ BUF[19];
        this.v2l ^= BUF[4] ^ BUF[20];
        this.v2h ^= BUF[5] ^ BUF[21];
        this.v3l ^= BUF[6] ^ BUF[22];
        this.v3h ^= BUF[7] ^ BUF[23];
        this.v4l ^= BUF[8] ^ BUF[24];
        this.v4h ^= BUF[9] ^ BUF[25];
        this.v5l ^= BUF[10] ^ BUF[26];
        this.v5h ^= BUF[11] ^ BUF[27];
        this.v6l ^= BUF[12] ^ BUF[28];
        this.v6h ^= BUF[13] ^ BUF[29];
        this.v7l ^= BUF[14] ^ BUF[30];
        this.v7h ^= BUF[15] ^ BUF[31];
        BUF.fill(0);
    }
    destroy() {
        this.destroyed = true;
        this.buffer32.fill(0);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}
exports.blake2b = (0, utils_js_1.wrapConstructorWithOpts)((opts) => new BLAKE2b(opts));

},{"./_blake2.js":1,"./_u64.js":2,"./utils.js":5}],4:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.crypto = void 0;
const crypto_1 = __importDefault(require("crypto"));
exports.crypto = {
    node: crypto_1.default,
    web: undefined,
};

},{"crypto":7}],5:[function(require,module,exports){
"use strict";
/*! noble-hashes - MIT License (c) 2021 Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomBytes = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.checkOpts = exports.Hash = exports.assertHash = exports.assertBool = exports.assertNumber = exports.toBytes = exports.asyncLoop = exports.nextTick = exports.bytesToHex = exports.isLE = exports.rotr = exports.createView = exports.u32 = exports.u8 = void 0;
// The import here is via the package name. This is to ensure
// that exports mapping/resolution does fall into place.
const crypto_1 = require("@noble/hashes/lib/crypto");
// Cast array to different type
const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
exports.u8 = u8;
const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
exports.u32 = u32;
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
exports.createView = createView;
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
exports.rotr = rotr;
exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
// There is almost no big endian hardware, but js typed arrays uses platform specific endianess.
// So, just to be sure not to corrupt anything.
if (!exports.isLE)
    throw new Error('Non little-endian hardware is not supported');
const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a) {
    // pre-caching chars could speed this up 6x.
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += hexes[uint8a[i]];
    }
    return hex;
}
exports.bytesToHex = bytesToHex;
// Currently avoid insertion of polyfills with packers (browserify/webpack/etc)
// But setTimeout is pretty slow, maybe worth to investigate howto do minimal polyfill here
exports.nextTick = (() => {
    const nodeRequire = typeof module !== 'undefined' &&
        typeof module.require === 'function' &&
        module.require.bind(module);
    try {
        if (nodeRequire) {
            const { setImmediate } = nodeRequire('timers');
            return () => new Promise((resolve) => setImmediate(resolve));
        }
    }
    catch (e) { }
    return () => new Promise((resolve) => setTimeout(resolve, 0));
})();
// Returns control to thread each 'tick' ms to avoid blocking
async function asyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
            continue;
        await (0, exports.nextTick)();
        ts += diff;
    }
}
exports.asyncLoop = asyncLoop;
function toBytes(data) {
    if (typeof data === 'string')
        data = new TextEncoder().encode(data);
    if (!(data instanceof Uint8Array))
        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    return data;
}
exports.toBytes = toBytes;
function assertNumber(n) {
    if (!Number.isSafeInteger(n))
        throw new Error(`Wrong integer: ${n}`);
}
exports.assertNumber = assertNumber;
function assertBool(b) {
    if (typeof b !== 'boolean') {
        throw new Error(`Expected boolean, not ${b}`);
    }
}
exports.assertBool = assertBool;
function assertHash(hash) {
    if (typeof hash !== 'function' || typeof hash.init !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    assertNumber(hash.outputLen);
    assertNumber(hash.blockLen);
}
exports.assertHash = assertHash;
// For runtime check if class implements interface
class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
exports.Hash = Hash;
// Check if object doens't have custom constructor (like Uint8Array/Array)
const isPlainObject = (obj) => Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;
function checkOpts(def, _opts) {
    if (_opts !== undefined && (typeof _opts !== 'object' || !isPlainObject(_opts)))
        throw new TypeError('Options should be object or undefined');
    const opts = Object.assign(def, _opts);
    return opts;
}
exports.checkOpts = checkOpts;
function wrapConstructor(hashConstructor) {
    const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
    const tmp = hashConstructor();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor();
    hashC.init = hashC.create;
    return hashC;
}
exports.wrapConstructor = wrapConstructor;
function wrapConstructorWithOpts(hashCons) {
    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
    const tmp = hashCons({});
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    hashC.init = hashC.create;
    return hashC;
}
exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
function randomBytes(bytesLength = 32) {
    if (crypto_1.crypto.web) {
        return crypto_1.crypto.web.getRandomValues(new Uint8Array(bytesLength));
    }
    else if (crypto_1.crypto.node) {
        return new Uint8Array(crypto_1.crypto.node.randomBytes(bytesLength).buffer);
    }
    else {
        throw new Error("The environment doesn't have randomBytes function");
    }
}
exports.randomBytes = randomBytes;

},{"@noble/hashes/lib/crypto":4}],6:[function(require,module,exports){
"use strict";
/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.utils = exports.schnorr = exports.verify = exports.signSync = exports.sign = exports.getSharedSecret = exports.recoverPublicKey = exports.getPublicKey = exports.SignResult = exports.Signature = exports.Point = exports.CURVE = void 0;
const crypto_1 = __importDefault(require("crypto"));
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _8n = BigInt(8);
const POW_2_256 = _2n ** BigInt(256);
const CURVE = {
    a: _0n,
    b: BigInt(7),
    P: POW_2_256 - _2n ** BigInt(32) - BigInt(977),
    n: POW_2_256 - BigInt('432420386565659656852420866394968145599'),
    h: _1n,
    Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
    Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
    beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
};
exports.CURVE = CURVE;
function weistrass(x) {
    const { a, b } = CURVE;
    return mod(x ** _3n + a * x + b);
}
const USE_ENDOMORPHISM = CURVE.a === _0n;
class JacobianPoint {
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    static fromAffine(p) {
        if (!(p instanceof Point)) {
            throw new TypeError('JacobianPoint#fromAffine: expected Point');
        }
        return new JacobianPoint(p.x, p.y, _1n);
    }
    static toAffineBatch(points) {
        const toInv = invertBatch(points.map((p) => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    static normalizeZ(points) {
        return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
    }
    equals(other) {
        const a = this;
        const b = other;
        const az2 = mod(a.z * a.z);
        const az3 = mod(a.z * az2);
        const bz2 = mod(b.z * b.z);
        const bz3 = mod(b.z * bz2);
        return mod(a.x * bz2) === mod(az2 * b.x) && mod(a.y * bz3) === mod(az3 * b.y);
    }
    negate() {
        return new JacobianPoint(this.x, mod(-this.y), this.z);
    }
    double() {
        const X1 = this.x;
        const Y1 = this.y;
        const Z1 = this.z;
        const A = mod(X1 ** _2n);
        const B = mod(Y1 ** _2n);
        const C = mod(B ** _2n);
        const D = mod(_2n * (mod(mod((X1 + B) ** _2n)) - A - C));
        const E = mod(_3n * A);
        const F = mod(E ** _2n);
        const X3 = mod(F - _2n * D);
        const Y3 = mod(E * (D - X3) - _8n * C);
        const Z3 = mod(_2n * Y1 * Z1);
        return new JacobianPoint(X3, Y3, Z3);
    }
    add(other) {
        if (!(other instanceof JacobianPoint)) {
            throw new TypeError('JacobianPoint#add: expected JacobianPoint');
        }
        const X1 = this.x;
        const Y1 = this.y;
        const Z1 = this.z;
        const X2 = other.x;
        const Y2 = other.y;
        const Z2 = other.z;
        if (X2 === _0n || Y2 === _0n)
            return this;
        if (X1 === _0n || Y1 === _0n)
            return other;
        const Z1Z1 = mod(Z1 ** _2n);
        const Z2Z2 = mod(Z2 ** _2n);
        const U1 = mod(X1 * Z2Z2);
        const U2 = mod(X2 * Z1Z1);
        const S1 = mod(Y1 * Z2 * Z2Z2);
        const S2 = mod(mod(Y2 * Z1) * Z1Z1);
        const H = mod(U2 - U1);
        const r = mod(S2 - S1);
        if (H === _0n) {
            if (r === _0n) {
                return this.double();
            }
            else {
                return JacobianPoint.ZERO;
            }
        }
        const HH = mod(H ** _2n);
        const HHH = mod(H * HH);
        const V = mod(U1 * HH);
        const X3 = mod(r ** _2n - HHH - _2n * V);
        const Y3 = mod(r * (V - X3) - S1 * HHH);
        const Z3 = mod(Z1 * Z2 * H);
        return new JacobianPoint(X3, Y3, Z3);
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiplyUnsafe(scalar) {
        let n = normalizeScalar(scalar);
        if (!USE_ENDOMORPHISM) {
            let p = JacobianPoint.ZERO;
            let d = this;
            while (n > _0n) {
                if (n & _1n)
                    p = p.add(d);
                d = d.double();
                n >>= _1n;
            }
            return p;
        }
        let { k1neg, k1, k2neg, k2 } = splitScalarEndo(n);
        let k1p = JacobianPoint.ZERO;
        let k2p = JacobianPoint.ZERO;
        let d = this;
        while (k1 > _0n || k2 > _0n) {
            if (k1 & _1n)
                k1p = k1p.add(d);
            if (k2 & _1n)
                k2p = k2p.add(d);
            d = d.double();
            k1 >>= _1n;
            k2 >>= _1n;
        }
        if (k1neg)
            k1p = k1p.negate();
        if (k2neg)
            k2p = k2p.negate();
        k2p = new JacobianPoint(mod(k2p.x * CURVE.beta), k2p.y, k2p.z);
        return k1p.add(k2p);
    }
    precomputeWindow(W) {
        const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
        let points = [];
        let p = this;
        let base = p;
        for (let window = 0; window < windows; window++) {
            base = p;
            points.push(base);
            for (let i = 1; i < 2 ** (W - 1); i++) {
                base = base.add(p);
                points.push(base);
            }
            p = base.double();
        }
        return points;
    }
    wNAF(n, affinePoint) {
        if (!affinePoint && this.equals(JacobianPoint.BASE))
            affinePoint = Point.BASE;
        const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
        if (256 % W) {
            throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
        }
        let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
        if (!precomputes) {
            precomputes = this.precomputeWindow(W);
            if (affinePoint && W !== 1) {
                precomputes = JacobianPoint.normalizeZ(precomputes);
                pointPrecomputes.set(affinePoint, precomputes);
            }
        }
        let p = JacobianPoint.ZERO;
        let f = JacobianPoint.ZERO;
        const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
        const windowSize = 2 ** (W - 1);
        const mask = BigInt(2 ** W - 1);
        const maxNumber = 2 ** W;
        const shiftBy = BigInt(W);
        for (let window = 0; window < windows; window++) {
            const offset = window * windowSize;
            let wbits = Number(n & mask);
            n >>= shiftBy;
            if (wbits > windowSize) {
                wbits -= maxNumber;
                n += _1n;
            }
            if (wbits === 0) {
                let pr = precomputes[offset];
                if (window % 2)
                    pr = pr.negate();
                f = f.add(pr);
            }
            else {
                let cached = precomputes[offset + Math.abs(wbits) - 1];
                if (wbits < 0)
                    cached = cached.negate();
                p = p.add(cached);
            }
        }
        return { p, f };
    }
    multiply(scalar, affinePoint) {
        let n = normalizeScalar(scalar);
        let point;
        let fake;
        if (USE_ENDOMORPHISM) {
            let { k1neg, k1, k2neg, k2 } = splitScalarEndo(n);
            let { p: k1p, f: f1p } = this.wNAF(k1, affinePoint);
            let { p: k2p, f: f2p } = this.wNAF(k2, affinePoint);
            if (k1neg)
                k1p = k1p.negate();
            if (k2neg)
                k2p = k2p.negate();
            k2p = new JacobianPoint(mod(k2p.x * CURVE.beta), k2p.y, k2p.z);
            point = k1p.add(k2p);
            fake = f1p.add(f2p);
        }
        else {
            let { p, f } = this.wNAF(n, affinePoint);
            point = p;
            fake = f;
        }
        return JacobianPoint.normalizeZ([point, fake])[0];
    }
    toAffine(invZ = invert(this.z)) {
        const invZ2 = invZ ** _2n;
        const x = mod(this.x * invZ2);
        const y = mod(this.y * invZ2 * invZ);
        return new Point(x, y);
    }
}
JacobianPoint.BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, _1n);
JacobianPoint.ZERO = new JacobianPoint(_0n, _1n, _0n);
const pointPrecomputes = new WeakMap();
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    _setWindowSize(windowSize) {
        this._WINDOW_SIZE = windowSize;
        pointPrecomputes.delete(this);
    }
    static fromCompressedHex(bytes) {
        const isShort = bytes.length === 32;
        const x = bytesToNumber(isShort ? bytes : bytes.slice(1));
        const y2 = weistrass(x);
        let y = sqrtMod(y2);
        const isYOdd = (y & _1n) === _1n;
        if (isShort) {
            if (isYOdd)
                y = mod(-y);
        }
        else {
            const isFirstByteOdd = (bytes[0] & 1) === 1;
            if (isFirstByteOdd !== isYOdd)
                y = mod(-y);
        }
        const point = new Point(x, y);
        point.assertValidity();
        return point;
    }
    static fromUncompressedHex(bytes) {
        const x = bytesToNumber(bytes.slice(1, 33));
        const y = bytesToNumber(bytes.slice(33));
        const point = new Point(x, y);
        point.assertValidity();
        return point;
    }
    static fromHex(hex) {
        const bytes = ensureBytes(hex);
        const header = bytes[0];
        if (bytes.length === 32 || (bytes.length === 33 && (header === 0x02 || header === 0x03))) {
            return this.fromCompressedHex(bytes);
        }
        if (bytes.length === 65 && header === 0x04)
            return this.fromUncompressedHex(bytes);
        throw new Error(`Point.fromHex: received invalid point. Expected 32-33 compressed bytes or 65 uncompressed bytes, not ${bytes.length}`);
    }
    static fromPrivateKey(privateKey) {
        return Point.BASE.multiply(normalizePrivateKey(privateKey));
    }
    static fromSignature(msgHash, signature, recovery) {
        let h = msgHash instanceof Uint8Array ? bytesToNumber(msgHash) : hexToNumber(msgHash);
        const sig = normalizeSignature(signature);
        const { r, s } = sig;
        if (recovery !== 0 && recovery !== 1) {
            throw new Error('Cannot recover signature: invalid yParity bit');
        }
        const prefix = 2 + (recovery & 1);
        const P_ = Point.fromHex(`0${prefix}${pad64(r)}`);
        const sP = JacobianPoint.fromAffine(P_).multiplyUnsafe(s);
        const hG = JacobianPoint.BASE.multiply(h);
        const rinv = invert(r, CURVE.n);
        const Q = sP.subtract(hG).multiplyUnsafe(rinv);
        const point = Q.toAffine();
        point.assertValidity();
        return point;
    }
    toRawBytes(isCompressed = false) {
        return hexToBytes(this.toHex(isCompressed));
    }
    toHex(isCompressed = false) {
        const x = pad64(this.x);
        if (isCompressed) {
            return `${this.y & _1n ? '03' : '02'}${x}`;
        }
        else {
            return `04${x}${pad64(this.y)}`;
        }
    }
    toHexX() {
        return this.toHex(true).slice(2);
    }
    toRawX() {
        return this.toRawBytes(true).slice(1);
    }
    assertValidity() {
        const msg = 'Point is not on elliptic curve';
        const { P } = CURVE;
        const { x, y } = this;
        if (x === _0n || y === _0n || x >= P || y >= P)
            throw new Error(msg);
        const left = mod(y * y);
        const right = weistrass(x);
        if ((left - right) % P !== _0n)
            throw new Error(msg);
    }
    equals(other) {
        return this.x === other.x && this.y === other.y;
    }
    negate() {
        return new Point(this.x, mod(-this.y));
    }
    double() {
        return JacobianPoint.fromAffine(this).double().toAffine();
    }
    add(other) {
        return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiply(scalar) {
        return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
    }
}
exports.Point = Point;
Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
Point.ZERO = new Point(_0n, _0n);
function sliceDer(s) {
    return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
}
class Signature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }
    static fromCompact(hex) {
        if (typeof hex !== 'string' && !(hex instanceof Uint8Array)) {
            throw new TypeError(`Signature.fromCompact: Expected string or Uint8Array`);
        }
        const str = hex instanceof Uint8Array ? bytesToHex(hex) : hex;
        if (str.length !== 128)
            throw new Error('Signature.fromCompact: Expected 64-byte hex');
        const sig = new Signature(hexToNumber(str.slice(0, 64)), hexToNumber(str.slice(64, 128)));
        sig.assertValidity();
        return sig;
    }
    static fromDER(hex) {
        const fn = 'Signature.fromDER';
        if (typeof hex !== 'string' && !(hex instanceof Uint8Array)) {
            throw new TypeError(`${fn}: Expected string or Uint8Array`);
        }
        const str = hex instanceof Uint8Array ? bytesToHex(hex) : hex;
        const length = parseByte(str.slice(2, 4));
        if (str.slice(0, 2) !== '30' || length !== str.length - 4 || str.slice(4, 6) !== '02') {
            throw new Error(`${fn}: Invalid signature ${str}`);
        }
        const rLen = parseByte(str.slice(6, 8));
        const rEnd = 8 + rLen;
        const rr = str.slice(8, rEnd);
        if (rr.startsWith('00') && parseByte(rr.slice(2, 4)) <= 0x7f) {
            throw new Error(`${fn}: Invalid r with trailing length`);
        }
        const r = hexToNumber(rr);
        const separator = str.slice(rEnd, rEnd + 2);
        if (separator !== '02') {
            throw new Error(`${fn}: Invalid r-s separator`);
        }
        const sLen = parseByte(str.slice(rEnd + 2, rEnd + 4));
        const diff = length - sLen - rLen - 10;
        if (diff > 0 || diff === -4) {
            throw new Error(`${fn}: Invalid total length`);
        }
        if (sLen > length - rLen - 4) {
            throw new Error(`${fn}: Invalid s`);
        }
        const sStart = rEnd + 4;
        const ss = str.slice(sStart, sStart + sLen);
        if (ss.startsWith('00') && parseByte(ss.slice(2, 4)) <= 0x7f) {
            throw new Error(`${fn}: Invalid s with trailing length`);
        }
        const s = hexToNumber(ss);
        const sig = new Signature(r, s);
        sig.assertValidity();
        return sig;
    }
    static fromHex(hex) {
        return this.fromDER(hex);
    }
    assertValidity() {
        const { r, s } = this;
        if (!isWithinCurveOrder(r))
            throw new Error('Invalid Signature: r must be 0 < r < n');
        if (!isWithinCurveOrder(s))
            throw new Error('Invalid Signature: s must be 0 < s < n');
    }
    toDERRawBytes(isCompressed = false) {
        return hexToBytes(this.toDERHex(isCompressed));
    }
    toDERHex(isCompressed = false) {
        const sHex = sliceDer(numberToHex(this.s));
        if (isCompressed)
            return sHex;
        const rHex = sliceDer(numberToHex(this.r));
        const rLen = numberToHex(rHex.length / 2);
        const sLen = numberToHex(sHex.length / 2);
        const length = numberToHex(rHex.length / 2 + sHex.length / 2 + 4);
        return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
    }
    toRawBytes() {
        return this.toDERRawBytes();
    }
    toHex() {
        return this.toDERHex();
    }
    toCompactRawBytes() {
        return hexToBytes(this.toCompactHex());
    }
    toCompactHex() {
        return pad64(this.r) + pad64(this.s);
    }
}
exports.Signature = Signature;
exports.SignResult = Signature;
function concatBytes(...arrays) {
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function bytesToHex(uint8a) {
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function pad64(num) {
    return num.toString(16).padStart(64, '0');
}
function pad32b(num) {
    return hexToBytes(pad64(num));
}
function numberToHex(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function hexToNumber(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
    }
    return BigInt(`0x${hex}`);
}
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}
function ensureBytes(hex) {
    return hex instanceof Uint8Array ? hex : hexToBytes(hex);
}
function bytesToNumber(bytes) {
    return hexToNumber(bytesToHex(bytes));
}
function parseByte(str) {
    return Number.parseInt(str, 16) * 2;
}
function normalizeScalar(num) {
    if (typeof num === 'number' && num > 0 && Number.isSafeInteger(num))
        return BigInt(num);
    if (typeof num === 'bigint' && isWithinCurveOrder(num))
        return num;
    throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
}
function mod(a, b = CURVE.P) {
    const result = a % b;
    return result >= 0 ? result : b + result;
}
function pow2(x, power) {
    const { P } = CURVE;
    let res = x;
    while (power-- > _0n) {
        res *= res;
        res %= P;
    }
    return res;
}
function sqrtMod(x) {
    const { P } = CURVE;
    const _6n = BigInt(6);
    const _11n = BigInt(11);
    const _22n = BigInt(22);
    const _23n = BigInt(23);
    const _44n = BigInt(44);
    const _88n = BigInt(88);
    const b2 = (x * x * x) % P;
    const b3 = (b2 * b2 * x) % P;
    const b6 = (pow2(b3, _3n) * b3) % P;
    const b9 = (pow2(b6, _3n) * b3) % P;
    const b11 = (pow2(b9, _2n) * b2) % P;
    const b22 = (pow2(b11, _11n) * b11) % P;
    const b44 = (pow2(b22, _22n) * b22) % P;
    const b88 = (pow2(b44, _44n) * b44) % P;
    const b176 = (pow2(b88, _88n) * b88) % P;
    const b220 = (pow2(b176, _44n) * b44) % P;
    const b223 = (pow2(b220, _3n) * b3) % P;
    const t1 = (pow2(b223, _23n) * b22) % P;
    const t2 = (pow2(t1, _6n) * b2) % P;
    return pow2(t2, _2n);
}
function invert(number, modulo = CURVE.P) {
    if (number === _0n || modulo <= _0n) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
    let a = mod(number, modulo);
    let b = modulo;
    let x = _0n, y = _1n, u = _1n, v = _0n;
    while (a !== _0n) {
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        const n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    const gcd = b;
    if (gcd !== _1n)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
function invertBatch(nums, n = CURVE.P) {
    const len = nums.length;
    const scratch = new Array(len);
    let acc = _1n;
    for (let i = 0; i < len; i++) {
        if (nums[i] === _0n)
            continue;
        scratch[i] = acc;
        acc = mod(acc * nums[i], n);
    }
    acc = invert(acc, n);
    for (let i = len - 1; i >= 0; i--) {
        if (nums[i] === _0n)
            continue;
        const tmp = mod(acc * nums[i], n);
        nums[i] = mod(acc * scratch[i], n);
        acc = tmp;
    }
    return nums;
}
const divNearest = (a, b) => (a + b / _2n) / b;
const POW_2_128 = _2n ** BigInt(128);
function splitScalarEndo(k) {
    const { n } = CURVE;
    const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
    const b1 = -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
    const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
    const b2 = a1;
    const c1 = divNearest(b2 * k, n);
    const c2 = divNearest(-b1 * k, n);
    let k1 = mod(k - c1 * a1 - c2 * a2, n);
    let k2 = mod(-c1 * b1 - c2 * b2, n);
    const k1neg = k1 > POW_2_128;
    const k2neg = k2 > POW_2_128;
    if (k1neg)
        k1 = n - k1;
    if (k2neg)
        k2 = n - k2;
    if (k1 > POW_2_128 || k2 > POW_2_128)
        throw new Error('splitScalarEndo: Endomorphism failed');
    return { k1neg, k1, k2neg, k2 };
}
function truncateHash(hash) {
    if (typeof hash !== 'string')
        hash = bytesToHex(hash);
    let msg = hexToNumber(hash || '0');
    const byteLength = hash.length / 2;
    const delta = byteLength * 8 - 256;
    if (delta > 0) {
        msg = msg >> BigInt(delta);
    }
    if (msg >= CURVE.n) {
        msg -= CURVE.n;
    }
    return msg;
}
function _abc6979(msgHash, privateKey) {
    if (msgHash == null)
        throw new Error(`sign: expected valid msgHash, not "${msgHash}"`);
    const num = typeof msgHash === 'string' ? hexToNumber(msgHash) : bytesToNumber(msgHash);
    const h1 = pad32b(num);
    const h1n = bytesToNumber(h1);
    const x = pad32b(privateKey);
    let v = new Uint8Array(32).fill(1);
    let k = new Uint8Array(32).fill(0);
    const b0 = Uint8Array.from([0x00]);
    const b1 = Uint8Array.from([0x01]);
    return { h1, h1n, x, v, k, b0, b1 };
}
async function getQRSrfc6979(msgHash, privateKey) {
    const privKey = normalizePrivateKey(privateKey);
    let { h1, h1n, x, v, k, b0, b1 } = _abc6979(msgHash, privKey);
    const hmac = exports.utils.hmacSha256;
    k = await hmac(k, v, b0, x, h1);
    v = await hmac(k, v);
    k = await hmac(k, v, b1, x, h1);
    v = await hmac(k, v);
    for (let i = 0; i < 1000; i++) {
        v = await hmac(k, v);
        let qrs = calcQRSFromK(v, h1n, privKey);
        if (qrs)
            return qrs;
        k = await hmac(k, v, b0);
        v = await hmac(k, v);
    }
    throw new TypeError('secp256k1: Tried 1,000 k values for sign(), all were invalid');
}
function getQRSrfc6979Sync(msgHash, privateKey) {
    const privKey = normalizePrivateKey(privateKey);
    let { h1, h1n, x, v, k, b0, b1 } = _abc6979(msgHash, privKey);
    const hmac = exports.utils.hmacSha256Sync;
    if (!hmac)
        throw new Error('utils.hmacSha256Sync is undefined, you need to set it');
    k = hmac(k, v, b0, x, h1);
    if (k instanceof Promise)
        throw new Error('To use sync sign(), ensure utils.hmacSha256 is sync');
    v = hmac(k, v);
    k = hmac(k, v, b1, x, h1);
    v = hmac(k, v);
    for (let i = 0; i < 1000; i++) {
        v = hmac(k, v);
        let qrs = calcQRSFromK(v, h1n, privKey);
        if (qrs)
            return qrs;
        k = hmac(k, v, b0);
        v = hmac(k, v);
    }
    throw new TypeError('secp256k1: Tried 1,000 k values for sign(), all were invalid');
}
function isWithinCurveOrder(num) {
    return 0 < num && num < CURVE.n;
}
function calcQRSFromK(v, msg, priv) {
    const k = bytesToNumber(v);
    if (!isWithinCurveOrder(k))
        return;
    const max = CURVE.n;
    const q = Point.BASE.multiply(k);
    const r = mod(q.x, max);
    const s = mod(invert(k, max) * (msg + r * priv), max);
    if (r === _0n || s === _0n)
        return;
    return [q, r, s];
}
function normalizePrivateKey(key) {
    let num;
    if (typeof key === 'bigint') {
        num = key;
    }
    else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
        num = BigInt(key);
    }
    else if (typeof key === 'string') {
        if (key.length !== 64)
            throw new Error('Expected 32 bytes of private key');
        num = hexToNumber(key);
    }
    else if (key instanceof Uint8Array) {
        if (key.length !== 32)
            throw new Error('Expected 32 bytes of private key');
        num = bytesToNumber(key);
    }
    else {
        throw new TypeError('Expected valid private key');
    }
    if (!isWithinCurveOrder(num))
        throw new Error('Expected private key: 0 < key < n');
    return num;
}
function normalizePublicKey(publicKey) {
    if (publicKey instanceof Point) {
        publicKey.assertValidity();
        return publicKey;
    }
    else {
        return Point.fromHex(publicKey);
    }
}
function normalizeSignature(signature) {
    if (signature instanceof Signature) {
        signature.assertValidity();
        return signature;
    }
    else {
        return Signature.fromDER(signature);
    }
}
function getPublicKey(privateKey, isCompressed = false) {
    const point = Point.fromPrivateKey(privateKey);
    if (typeof privateKey === 'string') {
        return point.toHex(isCompressed);
    }
    return point.toRawBytes(isCompressed);
}
exports.getPublicKey = getPublicKey;
function recoverPublicKey(msgHash, signature, recovery) {
    const point = Point.fromSignature(msgHash, signature, recovery);
    return typeof msgHash === 'string' ? point.toHex() : point.toRawBytes();
}
exports.recoverPublicKey = recoverPublicKey;
function isPub(item) {
    const arr = item instanceof Uint8Array;
    const str = typeof item === 'string';
    const len = (arr || str) && item.length;
    if (arr)
        return len === 33 || len === 65;
    if (str)
        return len === 66 || len === 130;
    if (item instanceof Point)
        return true;
    return false;
}
function getSharedSecret(privateA, publicB, isCompressed = false) {
    if (isPub(privateA))
        throw new TypeError('getSharedSecret: first arg must be private key');
    if (!isPub(publicB))
        throw new TypeError('getSharedSecret: second arg must be public key');
    const b = normalizePublicKey(publicB);
    b.assertValidity();
    const shared = b.multiply(normalizePrivateKey(privateA));
    return typeof privateA === 'string'
        ? shared.toHex(isCompressed)
        : shared.toRawBytes(isCompressed);
}
exports.getSharedSecret = getSharedSecret;
function QRSToSig(qrs, opts, str = false) {
    const [q, r, s] = qrs;
    let { canonical, der, recovered } = opts;
    let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n);
    let adjustedS = s;
    const HIGH_NUMBER = CURVE.n >> _1n;
    if (s > HIGH_NUMBER && canonical) {
        adjustedS = CURVE.n - s;
        recovery ^= 1;
    }
    const sig = new Signature(r, adjustedS);
    sig.assertValidity();
    const hex = der === false ? sig.toCompactHex() : sig.toDERHex();
    const hashed = str ? hex : hexToBytes(hex);
    return recovered ? [hashed, recovery] : hashed;
}
async function sign(msgHash, privKey, opts = {}) {
    return QRSToSig(await getQRSrfc6979(msgHash, privKey), opts, typeof msgHash === 'string');
}
exports.sign = sign;
function signSync(msgHash, privKey, opts = {}) {
    return QRSToSig(getQRSrfc6979Sync(msgHash, privKey), opts, typeof msgHash === 'string');
}
exports.signSync = signSync;
function verify(signature, msgHash, publicKey) {
    const { n } = CURVE;
    let sig;
    try {
        sig = normalizeSignature(signature);
    }
    catch (error) {
        return false;
    }
    const { r, s } = sig;
    const h = truncateHash(msgHash);
    if (h === _0n)
        return false;
    const pubKey = JacobianPoint.fromAffine(normalizePublicKey(publicKey));
    const s1 = invert(s, n);
    const u1 = mod(h * s1, n);
    const u2 = mod(r * s1, n);
    const Ghs1 = JacobianPoint.BASE.multiply(u1);
    const Prs1 = pubKey.multiplyUnsafe(u2);
    const R = Ghs1.add(Prs1).toAffine();
    const v = mod(R.x, n);
    return v === r;
}
exports.verify = verify;
async function taggedHash(tag, ...messages) {
    const tagB = new Uint8Array(tag.split('').map((c) => c.charCodeAt(0)));
    const tagH = await exports.utils.sha256(tagB);
    const h = await exports.utils.sha256(concatBytes(tagH, tagH, ...messages));
    return bytesToNumber(h);
}
async function createChallenge(x, P, message) {
    const rx = pad32b(x);
    const t = await taggedHash('BIP0340/challenge', rx, P.toRawX(), message);
    return mod(t, CURVE.n);
}
function hasEvenY(point) {
    return mod(point.y, _2n) === _0n;
}
class SchnorrSignature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
        if (r <= _0n || s <= _0n || r >= CURVE.P || s >= CURVE.n)
            throw new Error('Invalid signature');
    }
    static fromHex(hex) {
        const bytes = ensureBytes(hex);
        if (bytes.length !== 64) {
            throw new TypeError(`SchnorrSignature.fromHex: expected 64 bytes, not ${bytes.length}`);
        }
        const r = bytesToNumber(bytes.slice(0, 32));
        const s = bytesToNumber(bytes.slice(32));
        return new SchnorrSignature(r, s);
    }
    toHex() {
        return pad64(this.r) + pad64(this.s);
    }
    toRawBytes() {
        return hexToBytes(this.toHex());
    }
}
function schnorrGetPublicKey(privateKey) {
    const P = Point.fromPrivateKey(privateKey);
    return typeof privateKey === 'string' ? P.toHexX() : P.toRawX();
}
async function schnorrSign(msgHash, privateKey, auxRand = exports.utils.randomBytes()) {
    if (msgHash == null)
        throw new TypeError(`sign: Expected valid message, not "${msgHash}"`);
    if (!privateKey)
        privateKey = _0n;
    const { n } = CURVE;
    const m = ensureBytes(msgHash);
    const d0 = normalizePrivateKey(privateKey);
    const rand = ensureBytes(auxRand);
    if (rand.length !== 32)
        throw new TypeError('sign: Expected 32 bytes of aux randomness');
    const P = Point.fromPrivateKey(d0);
    const d = hasEvenY(P) ? d0 : n - d0;
    const t0h = await taggedHash('BIP0340/aux', rand);
    const t = d ^ t0h;
    const k0h = await taggedHash('BIP0340/nonce', pad32b(t), P.toRawX(), m);
    const k0 = mod(k0h, n);
    if (k0 === _0n)
        throw new Error('sign: Creation of signature failed. k is zero');
    const R = Point.fromPrivateKey(k0);
    const k = hasEvenY(R) ? k0 : n - k0;
    const e = await createChallenge(R.x, P, m);
    const sig = new SchnorrSignature(R.x, mod(k + e * d, n));
    const isValid = await schnorrVerify(sig.toRawBytes(), m, P.toRawX());
    if (!isValid)
        throw new Error('sign: Invalid signature produced');
    return typeof msgHash === 'string' ? sig.toHex() : sig.toRawBytes();
}
async function schnorrVerify(signature, msgHash, publicKey) {
    const sig = signature instanceof SchnorrSignature ? signature : SchnorrSignature.fromHex(signature);
    const m = typeof msgHash === 'string' ? hexToBytes(msgHash) : msgHash;
    const P = normalizePublicKey(publicKey);
    const e = await createChallenge(sig.r, P, m);
    const sG = Point.fromPrivateKey(sig.s);
    const eP = P.multiply(e);
    const R = sG.subtract(eP);
    if (R.equals(Point.BASE) || !hasEvenY(R) || R.x !== sig.r)
        return false;
    return true;
}
exports.schnorr = {
    Signature: SchnorrSignature,
    getPublicKey: schnorrGetPublicKey,
    sign: schnorrSign,
    verify: schnorrVerify,
};
Point.BASE._setWindowSize(8);
const crypto = {
    node: crypto_1.default,
    web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};
exports.utils = {
    isValidPrivateKey(privateKey) {
        try {
            normalizePrivateKey(privateKey);
            return true;
        }
        catch (error) {
            return false;
        }
    },
    randomBytes: (bytesLength = 32) => {
        if (crypto.web) {
            return crypto.web.getRandomValues(new Uint8Array(bytesLength));
        }
        else if (crypto.node) {
            const { randomBytes } = crypto.node;
            return new Uint8Array(randomBytes(bytesLength).buffer);
        }
        else {
            throw new Error("The environment doesn't have randomBytes function");
        }
    },
    randomPrivateKey: () => {
        let i = 8;
        while (i--) {
            const b32 = exports.utils.randomBytes(32);
            const num = bytesToNumber(b32);
            if (isWithinCurveOrder(num) && num !== _1n)
                return b32;
        }
        throw new Error('Valid private key was not found in 8 iterations. PRNG is broken');
    },
    sha256: async (message) => {
        if (crypto.web) {
            const buffer = await crypto.web.subtle.digest('SHA-256', message.buffer);
            return new Uint8Array(buffer);
        }
        else if (crypto.node) {
            const { createHash } = crypto.node;
            return Uint8Array.from(createHash('sha256').update(message).digest());
        }
        else {
            throw new Error("The environment doesn't have sha256 function");
        }
    },
    hmacSha256: async (key, ...messages) => {
        if (crypto.web) {
            const ckey = await crypto.web.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
            const message = concatBytes(...messages);
            const buffer = await crypto.web.subtle.sign('HMAC', ckey, message);
            return new Uint8Array(buffer);
        }
        else if (crypto.node) {
            const { createHmac } = crypto.node;
            const hash = createHmac('sha256', key);
            for (let message of messages) {
                hash.update(message);
            }
            return Uint8Array.from(hash.digest());
        }
        else {
            throw new Error("The environment doesn't have hmac-sha256 function");
        }
    },
    sha256Sync: undefined,
    hmacSha256Sync: undefined,
    precompute(windowSize = 8, point = Point.BASE) {
        const cached = point === Point.BASE ? point : new Point(point.x, point.y);
        cached._setWindowSize(windowSize);
        cached.multiply(_3n);
        return cached;
    },
};

},{"crypto":7}],7:[function(require,module,exports){

},{}],8:[function(require,module,exports){
const { blake2b } = require('@noble/hashes/lib/blake2b');
const { getPublicKey } = require('@noble/secp256k1');

console.log('blake2b', blake2b(new Uint8Array([1, 2, 3, 4])));
console.log('getPublicKey', getPublicKey(BigInt(0x01020304)));

},{"@noble/hashes/lib/blake2b":3,"@noble/secp256k1":6}]},{},[8]);
