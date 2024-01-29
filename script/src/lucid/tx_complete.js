"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TxComplete = void 0;
const mod_js_1 = require("../core/mod.js");
const tx_signed_js_1 = require("./tx_signed.js");
const mod_js_2 = require("../utils/mod.js");
class TxComplete {
    constructor(lucid, tx) {
        Object.defineProperty(this, "txComplete", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "witnessSetBuilder", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "tasks", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "lucid", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "fee", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "exUnits", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        this.lucid = lucid;
        this.txComplete = tx;
        this.witnessSetBuilder = mod_js_1.C.TransactionWitnessSetBuilder.new();
        this.tasks = [];
        this.fee = parseInt(tx.body().fee().to_str());
        const redeemers = tx.witness_set().redeemers();
        if (redeemers) {
            const exUnits = { cpu: 0, mem: 0 };
            for (let i = 0; i < redeemers.len(); i++) {
                const redeemer = redeemers.get(i);
                exUnits.cpu += parseInt(redeemer.ex_units().steps().to_str());
                exUnits.mem += parseInt(redeemer.ex_units().mem().to_str());
            }
            this.exUnits = exUnits;
        }
    }
    sign() {
        this.tasks.push(async () => {
            const witnesses = await this.lucid.wallet.signTx(this.txComplete);
            this.witnessSetBuilder.add_existing(witnesses);
        });
        return this;
    }
    /** Add an extra signature from a private key. */
    signWithPrivateKey(privateKey) {
        const priv = mod_js_1.C.PrivateKey.from_bech32(privateKey);
        const witness = mod_js_1.C.make_vkey_witness(mod_js_1.C.hash_transaction(this.txComplete.body()), priv);
        this.witnessSetBuilder.add_vkey(witness);
        return this;
    }
    /** Sign the transaction and return the witnesses that were just made. */
    async partialSign() {
        const witnesses = await this.lucid.wallet.signTx(this.txComplete);
        this.witnessSetBuilder.add_existing(witnesses);
        return (0, mod_js_2.toHex)(witnesses.to_bytes());
    }
    /**
     * Sign the transaction and return the witnesses that were just made.
     * Add an extra signature from a private key.
     */
    partialSignWithPrivateKey(privateKey) {
        const priv = mod_js_1.C.PrivateKey.from_bech32(privateKey);
        const witness = mod_js_1.C.make_vkey_witness(mod_js_1.C.hash_transaction(this.txComplete.body()), priv);
        this.witnessSetBuilder.add_vkey(witness);
        const witnesses = mod_js_1.C.TransactionWitnessSetBuilder.new();
        witnesses.add_vkey(witness);
        return (0, mod_js_2.toHex)(witnesses.build().to_bytes());
    }
    /** Sign the transaction with the given witnesses. */
    assemble(witnesses) {
        witnesses.forEach((witness) => {
            const witnessParsed = mod_js_1.C.TransactionWitnessSet.from_bytes((0, mod_js_2.fromHex)(witness));
            this.witnessSetBuilder.add_existing(witnessParsed);
        });
        return this;
    }
    async complete() {
        for (const task of this.tasks) {
            await task();
        }
        this.witnessSetBuilder.add_existing(this.txComplete.witness_set());
        const signedTx = mod_js_1.C.Transaction.new(this.txComplete.body(), this.witnessSetBuilder.build(), this.txComplete.auxiliary_data());
        return new tx_signed_js_1.TxSigned(this.lucid, signedTx);
    }
    /** Return the transaction in Hex encoded Cbor. */
    toString() {
        return (0, mod_js_2.toHex)(this.txComplete.to_bytes());
    }
    /** Return the transaction hash. */
    toHash() {
        return mod_js_1.C.hash_transaction(this.txComplete.body()).to_hex();
    }
}
exports.TxComplete = TxComplete;
