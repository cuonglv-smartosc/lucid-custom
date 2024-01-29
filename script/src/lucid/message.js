"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Message = void 0;
const sign_data_js_1 = require("../misc/sign_data.js");
const mod_js_1 = require("../mod.js");
class Message {
    constructor(lucid, address, payload) {
        Object.defineProperty(this, "lucid", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "address", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "payload", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.lucid = lucid;
        this.address = address;
        this.payload = payload;
    }
    /** Sign message with selected wallet. */
    sign() {
        return this.lucid.wallet.signMessage(this.address, this.payload);
    }
    /** Sign message with a separate private key. */
    signWithPrivateKey(privateKey) {
        const { paymentCredential, stakeCredential, address: { hex: hexAddress } } = this.lucid.utils.getAddressDetails(this.address);
        const keyHash = paymentCredential?.hash || stakeCredential?.hash;
        const keyHashOriginal = mod_js_1.C.PrivateKey.from_bech32(privateKey).to_public()
            .hash().to_hex();
        if (!keyHash || keyHash !== keyHashOriginal) {
            throw new Error(`Cannot sign message for address: ${this.address}.`);
        }
        return (0, sign_data_js_1.signData)(hexAddress, this.payload, privateKey);
    }
}
exports.Message = Message;
