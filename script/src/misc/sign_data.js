"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyData = exports.signData = void 0;
const mod_js_1 = require("../mod.js");
function signData(addressHex, payload, privateKey) {
    const protectedHeaders = mod_js_1.M.HeaderMap.new();
    protectedHeaders.set_algorithm_id(mod_js_1.M.Label.from_algorithm_id(mod_js_1.M.AlgorithmId.EdDSA));
    protectedHeaders.set_header(mod_js_1.M.Label.new_text("address"), mod_js_1.M.CBORValue.new_bytes((0, mod_js_1.fromHex)(addressHex)));
    const protectedSerialized = mod_js_1.M.ProtectedHeaderMap.new(protectedHeaders);
    const unprotectedHeaders = mod_js_1.M.HeaderMap.new();
    const headers = mod_js_1.M.Headers.new(protectedSerialized, unprotectedHeaders);
    const builder = mod_js_1.M.COSESign1Builder.new(headers, (0, mod_js_1.fromHex)(payload), false);
    const toSign = builder.make_data_to_sign().to_bytes();
    const priv = mod_js_1.C.PrivateKey.from_bech32(privateKey);
    const signedSigStruc = priv.sign(toSign).to_bytes();
    const coseSign1 = builder.build(signedSigStruc);
    const key = mod_js_1.M.COSEKey.new(mod_js_1.M.Label.from_key_type(mod_js_1.M.KeyType.OKP));
    key.set_algorithm_id(mod_js_1.M.Label.from_algorithm_id(mod_js_1.M.AlgorithmId.EdDSA));
    key.set_header(mod_js_1.M.Label.new_int(mod_js_1.M.Int.new_negative(mod_js_1.M.BigNum.from_str("1"))), mod_js_1.M.CBORValue.new_int(mod_js_1.M.Int.new_i32(6))); // crv (-1) set to Ed25519 (6)
    key.set_header(mod_js_1.M.Label.new_int(mod_js_1.M.Int.new_negative(mod_js_1.M.BigNum.from_str("2"))), mod_js_1.M.CBORValue.new_bytes(priv.to_public().as_bytes())); // x (-2) set to public key
    return {
        signature: (0, mod_js_1.toHex)(coseSign1.to_bytes()),
        key: (0, mod_js_1.toHex)(key.to_bytes()),
    };
}
exports.signData = signData;
function verifyData(addressHex, keyHash, payload, signedMessage) {
    const cose1 = mod_js_1.M.COSESign1.from_bytes((0, mod_js_1.fromHex)(signedMessage.signature));
    const key = mod_js_1.M.COSEKey.from_bytes((0, mod_js_1.fromHex)(signedMessage.key));
    const protectedHeaders = cose1.headers().protected()
        .deserialized_headers();
    const cose1Address = (() => {
        try {
            return (0, mod_js_1.toHex)(protectedHeaders.header(mod_js_1.M.Label.new_text("address"))?.as_bytes());
        }
        catch (_e) {
            throw new Error("No address found in signature.");
        }
    })();
    const cose1AlgorithmId = (() => {
        try {
            const int = protectedHeaders.algorithm_id()?.as_int();
            if (int?.is_positive())
                return parseInt(int.as_positive()?.to_str());
            return parseInt(int?.as_negative()?.to_str());
        }
        catch (_e) {
            throw new Error("Failed to retrieve Algorithm Id.");
        }
    })();
    const keyAlgorithmId = (() => {
        try {
            const int = key.algorithm_id()?.as_int();
            if (int?.is_positive())
                return parseInt(int.as_positive()?.to_str());
            return parseInt(int?.as_negative()?.to_str());
        }
        catch (_e) {
            throw new Error("Failed to retrieve Algorithm Id.");
        }
    })();
    const keyCurve = (() => {
        try {
            const int = key.header(mod_js_1.M.Label.new_int(mod_js_1.M.Int.new_negative(mod_js_1.M.BigNum.from_str("1"))))?.as_int();
            if (int?.is_positive())
                return parseInt(int.as_positive()?.to_str());
            return parseInt(int?.as_negative()?.to_str());
        }
        catch (_e) {
            throw new Error("Failed to retrieve Curve.");
        }
    })();
    const keyType = (() => {
        try {
            const int = key.key_type().as_int();
            if (int?.is_positive())
                return parseInt(int.as_positive()?.to_str());
            return parseInt(int?.as_negative()?.to_str());
        }
        catch (_e) {
            throw new Error("Failed to retrieve Key Type.");
        }
    })();
    const publicKey = (() => {
        try {
            return mod_js_1.C.PublicKey.from_bytes(key.header(mod_js_1.M.Label.new_int(mod_js_1.M.Int.new_negative(mod_js_1.M.BigNum.from_str("2"))))?.as_bytes());
        }
        catch (_e) {
            throw new Error("No public key found.");
        }
    })();
    const cose1Payload = (() => {
        try {
            return (0, mod_js_1.toHex)(cose1.payload());
        }
        catch (_e) {
            throw new Error("No payload found.");
        }
    })();
    const signature = mod_js_1.C.Ed25519Signature.from_bytes(cose1.signature());
    const data = cose1.signed_data(undefined, undefined).to_bytes();
    if (cose1Address !== addressHex)
        return false;
    if (keyHash !== publicKey.hash().to_hex())
        return false;
    if (cose1AlgorithmId !== keyAlgorithmId &&
        cose1AlgorithmId !== mod_js_1.M.AlgorithmId.EdDSA) {
        return false;
    }
    if (keyCurve !== 6)
        return false;
    if (keyType !== 1)
        return false;
    if (cose1Payload !== payload)
        return false;
    return publicKey.verify(data, signature);
}
exports.verifyData = verifyData;
