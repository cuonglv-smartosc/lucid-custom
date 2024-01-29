"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
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
exports.Tx = void 0;
const dntShim = __importStar(require("../../_dnt.shims.js"));
const mod_js_1 = require("../core/mod.js");
const mod_js_2 = require("../mod.js");
const mod_js_3 = require("../utils/mod.js");
const utils_js_1 = require("../utils/utils.js");
const tx_complete_js_1 = require("./tx_complete.js");
class Tx {
    constructor(lucid) {
        Object.defineProperty(this, "txBuilder", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        /** Stores the tx instructions, which get executed after calling .complete() */
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
        this.lucid = lucid;
        this.txBuilder = mod_js_1.C.TransactionBuilder.new(this.lucid.txBuilderConfig);
        this.tasks = [];
    }
    /** Read data from utxos. These utxos are only referenced and not spent. */
    readFrom(utxos) {
        this.tasks.push(async (that) => {
            for (const utxo of utxos) {
                if (utxo.datumHash) {
                    utxo.datum = mod_js_2.Data.to(await that.lucid.datumOf(utxo));
                    // Add datum to witness set, so it can be read from validators
                    const plutusData = mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(utxo.datum));
                    that.txBuilder.add_plutus_data(plutusData);
                }
                const coreUtxo = (0, mod_js_3.utxoToCore)(utxo);
                that.txBuilder.add_reference_input(coreUtxo);
            }
        });
        return this;
    }
    /**
     * A public key or native script input.
     * With redeemer it's a plutus script input.
     */
    collectFrom(utxos, redeemer) {
        this.tasks.push(async (that) => {
            for (const utxo of utxos) {
                if (utxo.datumHash && !utxo.datum) {
                    utxo.datum = mod_js_2.Data.to(await that.lucid.datumOf(utxo));
                }
                const coreUtxo = (0, mod_js_3.utxoToCore)(utxo);
                that.txBuilder.add_input(coreUtxo, redeemer &&
                    mod_js_1.C.ScriptWitness.new_plutus_witness(mod_js_1.C.PlutusWitness.new(mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(redeemer)), utxo.datumHash && utxo.datum
                        ? mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(utxo.datum))
                        : undefined, undefined)));
            }
        });
        return this;
    }
    /**
     * All assets should be of the same policy id.
     * You can chain mintAssets functions together if you need to mint assets with different policy ids.
     * If the plutus script doesn't need a redeemer, you still need to specifiy the void redeemer.
     */
    mintAssets(assets, redeemer) {
        this.tasks.push((that) => {
            const units = Object.keys(assets);
            const policyId = units[0].slice(0, 56);
            const mintAssets = mod_js_1.C.MintAssets.new();
            units.forEach((unit) => {
                if (unit.slice(0, 56) !== policyId) {
                    throw new Error("Only one policy id allowed. You can chain multiple mintAssets functions together if you need to mint assets with different policy ids.");
                }
                mintAssets.insert(mod_js_1.C.AssetName.new((0, mod_js_3.fromHex)(unit.slice(56))), mod_js_1.C.Int.from_str(assets[unit].toString()));
            });
            const scriptHash = mod_js_1.C.ScriptHash.from_bytes((0, mod_js_3.fromHex)(policyId));
            that.txBuilder.add_mint(scriptHash, mintAssets, redeemer
                ? mod_js_1.C.ScriptWitness.new_plutus_witness(mod_js_1.C.PlutusWitness.new(mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(redeemer)), undefined, undefined))
                : undefined);
        });
        return this;
    }
    /** Pay to a public key or native script address. */
    payToAddress(address, assets) {
        this.tasks.push((that) => {
            const output = mod_js_1.C.TransactionOutput.new(addressFromWithNetworkCheck(address, that.lucid), (0, mod_js_3.assetsToValue)(assets));
            that.txBuilder.add_output(output);
        });
        return this;
    }
    /** Pay to a public key or native script address with datum or scriptRef. */
    payToAddressWithData(address, outputData, assets) {
        this.tasks.push((that) => {
            if (typeof outputData === "string") {
                outputData = { asHash: outputData };
            }
            if ([outputData.hash, outputData.asHash, outputData.inline].filter((b) => b)
                .length > 1) {
                throw new Error("Not allowed to set hash, asHash and inline at the same time.");
            }
            const output = mod_js_1.C.TransactionOutput.new(addressFromWithNetworkCheck(address, that.lucid), (0, mod_js_3.assetsToValue)(assets));
            if (outputData.hash) {
                output.set_datum(mod_js_1.C.Datum.new_data_hash(mod_js_1.C.DataHash.from_hex(outputData.hash)));
            }
            else if (outputData.asHash) {
                const plutusData = mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(outputData.asHash));
                output.set_datum(mod_js_1.C.Datum.new_data_hash(mod_js_1.C.hash_plutus_data(plutusData)));
                that.txBuilder.add_plutus_data(plutusData);
            }
            else if (outputData.inline) {
                const plutusData = mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(outputData.inline));
                output.set_datum(mod_js_1.C.Datum.new_data(mod_js_1.C.Data.new(plutusData)));
            }
            const script = outputData.scriptRef;
            if (script) {
                output.set_script_ref((0, mod_js_3.toScriptRef)(script));
            }
            that.txBuilder.add_output(output);
        });
        return this;
    }
    /** Pay to a plutus script address with datum or scriptRef. */
    payToContract(address, outputData, assets) {
        if (typeof outputData === "string") {
            outputData = { asHash: outputData };
        }
        if (!(outputData.hash || outputData.asHash || outputData.inline)) {
            throw new Error("No datum set. Script output becomes unspendable without datum.");
        }
        return this.payToAddressWithData(address, outputData, assets);
    }
    /** Delegate to a stake pool. */
    delegateTo(rewardAddress, poolId, redeemer) {
        this.tasks.push((that) => {
            const addressDetails = that.lucid.utils.getAddressDetails(rewardAddress);
            if (addressDetails.type !== "Reward" ||
                !addressDetails.stakeCredential) {
                throw new Error("Not a reward address provided.");
            }
            const credential = addressDetails.stakeCredential.type === "Key"
                ? mod_js_1.C.StakeCredential.from_keyhash(mod_js_1.C.Ed25519KeyHash.from_bytes((0, mod_js_3.fromHex)(addressDetails.stakeCredential.hash)))
                : mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_bytes((0, mod_js_3.fromHex)(addressDetails.stakeCredential.hash)));
            that.txBuilder.add_certificate(mod_js_1.C.Certificate.new_stake_delegation(mod_js_1.C.StakeDelegation.new(credential, mod_js_1.C.Ed25519KeyHash.from_bech32(poolId))), redeemer
                ? mod_js_1.C.ScriptWitness.new_plutus_witness(mod_js_1.C.PlutusWitness.new(mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(redeemer)), undefined, undefined))
                : undefined);
        });
        return this;
    }
    /** Register a reward address in order to delegate to a pool and receive rewards. */
    registerStake(rewardAddress) {
        this.tasks.push((that) => {
            const addressDetails = that.lucid.utils.getAddressDetails(rewardAddress);
            if (addressDetails.type !== "Reward" ||
                !addressDetails.stakeCredential) {
                throw new Error("Not a reward address provided.");
            }
            const credential = addressDetails.stakeCredential.type === "Key"
                ? mod_js_1.C.StakeCredential.from_keyhash(mod_js_1.C.Ed25519KeyHash.from_bytes((0, mod_js_3.fromHex)(addressDetails.stakeCredential.hash)))
                : mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_bytes((0, mod_js_3.fromHex)(addressDetails.stakeCredential.hash)));
            that.txBuilder.add_certificate(mod_js_1.C.Certificate.new_stake_registration(mod_js_1.C.StakeRegistration.new(credential)), undefined);
        });
        return this;
    }
    /** Deregister a reward address. */
    deregisterStake(rewardAddress, redeemer) {
        this.tasks.push((that) => {
            const addressDetails = that.lucid.utils.getAddressDetails(rewardAddress);
            if (addressDetails.type !== "Reward" ||
                !addressDetails.stakeCredential) {
                throw new Error("Not a reward address provided.");
            }
            const credential = addressDetails.stakeCredential.type === "Key"
                ? mod_js_1.C.StakeCredential.from_keyhash(mod_js_1.C.Ed25519KeyHash.from_bytes((0, mod_js_3.fromHex)(addressDetails.stakeCredential.hash)))
                : mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_bytes((0, mod_js_3.fromHex)(addressDetails.stakeCredential.hash)));
            that.txBuilder.add_certificate(mod_js_1.C.Certificate.new_stake_deregistration(mod_js_1.C.StakeDeregistration.new(credential)), redeemer
                ? mod_js_1.C.ScriptWitness.new_plutus_witness(mod_js_1.C.PlutusWitness.new(mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(redeemer)), undefined, undefined))
                : undefined);
        });
        return this;
    }
    /** Register a stake pool. A pool deposit is required. The metadataUrl needs to be hosted already before making the registration. */
    registerPool(poolParams) {
        this.tasks.push(async (that) => {
            const poolRegistration = await createPoolRegistration(poolParams, that.lucid);
            const certificate = mod_js_1.C.Certificate.new_pool_registration(poolRegistration);
            that.txBuilder.add_certificate(certificate, undefined);
        });
        return this;
    }
    /** Update a stake pool. No pool deposit is required. The metadataUrl needs to be hosted already before making the update. */
    updatePool(poolParams) {
        this.tasks.push(async (that) => {
            const poolRegistration = await createPoolRegistration(poolParams, that.lucid);
            // This flag makes sure a pool deposit is not required
            poolRegistration.set_is_update(true);
            const certificate = mod_js_1.C.Certificate.new_pool_registration(poolRegistration);
            that.txBuilder.add_certificate(certificate, undefined);
        });
        return this;
    }
    /**
     * Retire a stake pool. The epoch needs to be the greater than the current epoch + 1 and less than current epoch + eMax.
     * The pool deposit will be sent to reward address as reward after full retirement of the pool.
     */
    retirePool(poolId, epoch) {
        this.tasks.push((that) => {
            const certificate = mod_js_1.C.Certificate.new_pool_retirement(mod_js_1.C.PoolRetirement.new(mod_js_1.C.Ed25519KeyHash.from_bech32(poolId), epoch));
            that.txBuilder.add_certificate(certificate, undefined);
        });
        return this;
    }
    withdraw(rewardAddress, amount, redeemer) {
        this.tasks.push((that) => {
            that.txBuilder.add_withdrawal(mod_js_1.C.RewardAddress.from_address(addressFromWithNetworkCheck(rewardAddress, that.lucid)), mod_js_1.C.BigNum.from_str(amount.toString()), redeemer
                ? mod_js_1.C.ScriptWitness.new_plutus_witness(mod_js_1.C.PlutusWitness.new(mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(redeemer)), undefined, undefined))
                : undefined);
        });
        return this;
    }
    /**
     * Needs to be a public key address.
     * The PaymentKeyHash is taken when providing a Base, Enterprise or Pointer address.
     * The StakeKeyHash is taken when providing a Reward address.
     */
    addSigner(address) {
        const addressDetails = this.lucid.utils.getAddressDetails(address);
        if (!addressDetails.paymentCredential && !addressDetails.stakeCredential) {
            throw new Error("Not a valid address.");
        }
        const credential = addressDetails.type === "Reward"
            ? addressDetails.stakeCredential
            : addressDetails.paymentCredential;
        if (credential.type === "Script") {
            throw new Error("Only key hashes are allowed as signers.");
        }
        return this.addSignerKey(credential.hash);
    }
    /** Add a payment or stake key hash as a required signer of the transaction. */
    addSignerKey(keyHash) {
        this.tasks.push((that) => {
            that.txBuilder.add_required_signer(mod_js_1.C.Ed25519KeyHash.from_bytes((0, mod_js_3.fromHex)(keyHash)));
        });
        return this;
    }
    validFrom(unixTime) {
        this.tasks.push((that) => {
            const slot = that.lucid.utils.unixTimeToSlot(unixTime);
            that.txBuilder.set_validity_start_interval(mod_js_1.C.BigNum.from_str(slot.toString()));
        });
        return this;
    }
    validTo(unixTime) {
        this.tasks.push((that) => {
            const slot = that.lucid.utils.unixTimeToSlot(unixTime);
            that.txBuilder.set_ttl(mod_js_1.C.BigNum.from_str(slot.toString()));
        });
        return this;
    }
    attachMetadata(label, metadata) {
        this.tasks.push((that) => {
            that.txBuilder.add_json_metadatum(mod_js_1.C.BigNum.from_str(label.toString()), JSON.stringify(metadata));
        });
        return this;
    }
    /** Converts strings to bytes if prefixed with **'0x'**. */
    attachMetadataWithConversion(label, metadata) {
        this.tasks.push((that) => {
            that.txBuilder.add_json_metadatum_with_schema(mod_js_1.C.BigNum.from_str(label.toString()), JSON.stringify(metadata), mod_js_1.C.MetadataJsonSchema.BasicConversions);
        });
        return this;
    }
    /** Explicitely set the network id in the transaction body. */
    addNetworkId(id) {
        this.tasks.push((that) => {
            that.txBuilder.set_network_id(mod_js_1.C.NetworkId.from_bytes((0, mod_js_3.fromHex)(id.toString(16).padStart(2, "0"))));
        });
        return this;
    }
    attachSpendingValidator(spendingValidator) {
        this.tasks.push((that) => {
            attachScript(that, spendingValidator);
        });
        return this;
    }
    attachMintingPolicy(mintingPolicy) {
        this.tasks.push((that) => {
            attachScript(that, mintingPolicy);
        });
        return this;
    }
    attachCertificateValidator(certValidator) {
        this.tasks.push((that) => {
            attachScript(that, certValidator);
        });
        return this;
    }
    attachWithdrawalValidator(withdrawalValidator) {
        this.tasks.push((that) => {
            attachScript(that, withdrawalValidator);
        });
        return this;
    }
    /** Compose transactions. */
    compose(tx) {
        if (tx)
            this.tasks = this.tasks.concat(tx.tasks);
        return this;
    }
    async complete(options) {
        if ([
            options?.change?.outputData?.hash,
            options?.change?.outputData?.asHash,
            options?.change?.outputData?.inline,
        ].filter((b) => b)
            .length > 1) {
            throw new Error("Not allowed to set hash, asHash and inline at the same time.");
        }
        let task = this.tasks.shift();
        while (task) {
            await task(this);
            task = this.tasks.shift();
        }
        const utxos = await this.lucid.wallet.getUtxosCore();
        const changeAddress = addressFromWithNetworkCheck(options?.change?.address || (await this.lucid.wallet.address()), this.lucid);
        if (options?.coinSelection || options?.coinSelection === undefined) {
            this.txBuilder.add_inputs_from(utxos, changeAddress, Uint32Array.from([
                200,
                1000,
                1500,
                800,
                800,
                5000, // weight utxos
            ]));
        }
        this.txBuilder.balance(changeAddress, (() => {
            if (options?.change?.outputData?.hash) {
                return mod_js_1.C.Datum.new_data_hash(mod_js_1.C.DataHash.from_hex(options.change.outputData.hash));
            }
            else if (options?.change?.outputData?.asHash) {
                this.txBuilder.add_plutus_data(mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(options.change.outputData.asHash)));
                return mod_js_1.C.Datum.new_data_hash(mod_js_1.C.hash_plutus_data(mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(options.change.outputData.asHash))));
            }
            else if (options?.change?.outputData?.inline) {
                return mod_js_1.C.Datum.new_data(mod_js_1.C.Data.new(mod_js_1.C.PlutusData.from_bytes((0, mod_js_3.fromHex)(options.change.outputData.inline))));
            }
            else {
                return undefined;
            }
        })());
        return new tx_complete_js_1.TxComplete(this.lucid, await this.txBuilder.construct(utxos, changeAddress, options?.nativeUplc === undefined ? true : options?.nativeUplc));
    }
    /** Return the current transaction body in Hex encoded Cbor. */
    async toString() {
        let task = this.tasks.shift();
        while (task) {
            await task(this);
            task = this.tasks.shift();
        }
        return (0, mod_js_3.toHex)(this.txBuilder.to_bytes());
    }
}
exports.Tx = Tx;
function attachScript(tx, { type, script }) {
    if (type === "Native") {
        return tx.txBuilder.add_native_script(mod_js_1.C.NativeScript.from_bytes((0, mod_js_3.fromHex)(script)));
    }
    else if (type === "PlutusV1") {
        return tx.txBuilder.add_plutus_script(mod_js_1.C.PlutusScript.from_bytes((0, mod_js_3.fromHex)((0, utils_js_1.applyDoubleCborEncoding)(script))));
    }
    else if (type === "PlutusV2") {
        return tx.txBuilder.add_plutus_v2_script(mod_js_1.C.PlutusScript.from_bytes((0, mod_js_3.fromHex)((0, utils_js_1.applyDoubleCborEncoding)(script))));
    }
    throw new Error("No variant matched.");
}
async function createPoolRegistration(poolParams, lucid) {
    const poolOwners = mod_js_1.C.Ed25519KeyHashes.new();
    poolParams.owners.forEach((owner) => {
        const { stakeCredential } = lucid.utils.getAddressDetails(owner);
        if (stakeCredential?.type === "Key") {
            poolOwners.add(mod_js_1.C.Ed25519KeyHash.from_hex(stakeCredential.hash));
        }
        else
            throw new Error("Only key hashes allowed for pool owners.");
    });
    const metadata = poolParams.metadataUrl
        ? await dntShim.fetch(poolParams.metadataUrl)
            .then((res) => res.arrayBuffer())
        : null;
    const metadataHash = metadata
        ? mod_js_1.C.PoolMetadataHash.from_bytes(mod_js_1.C.hash_blake2b256(new Uint8Array(metadata)))
        : null;
    const relays = mod_js_1.C.Relays.new();
    poolParams.relays.forEach((relay) => {
        switch (relay.type) {
            case "SingleHostIp": {
                const ipV4 = relay.ipV4
                    ? mod_js_1.C.Ipv4.new(new Uint8Array(relay.ipV4.split(".").map((b) => parseInt(b))))
                    : undefined;
                const ipV6 = relay.ipV6
                    ? mod_js_1.C.Ipv6.new((0, mod_js_3.fromHex)(relay.ipV6.replaceAll(":", "")))
                    : undefined;
                relays.add(mod_js_1.C.Relay.new_single_host_addr(mod_js_1.C.SingleHostAddr.new(relay.port, ipV4, ipV6)));
                break;
            }
            case "SingleHostDomainName": {
                relays.add(mod_js_1.C.Relay.new_single_host_name(mod_js_1.C.SingleHostName.new(relay.port, mod_js_1.C.DNSRecordAorAAAA.new(relay.domainName))));
                break;
            }
            case "MultiHost": {
                relays.add(mod_js_1.C.Relay.new_multi_host_name(mod_js_1.C.MultiHostName.new(mod_js_1.C.DNSRecordSRV.new(relay.domainName))));
                break;
            }
        }
    });
    return mod_js_1.C.PoolRegistration.new(mod_js_1.C.PoolParams.new(mod_js_1.C.Ed25519KeyHash.from_bech32(poolParams.poolId), mod_js_1.C.VRFKeyHash.from_hex(poolParams.vrfKeyHash), mod_js_1.C.BigNum.from_str(poolParams.pledge.toString()), mod_js_1.C.BigNum.from_str(poolParams.cost.toString()), mod_js_1.C.UnitInterval.from_float(poolParams.margin), mod_js_1.C.RewardAddress.from_address(addressFromWithNetworkCheck(poolParams.rewardAddress, lucid)), poolOwners, relays, metadataHash
        ? mod_js_1.C.PoolMetadata.new(mod_js_1.C.Url.new(poolParams.metadataUrl), metadataHash)
        : undefined));
}
function addressFromWithNetworkCheck(address, lucid) {
    const { type, networkId } = lucid.utils.getAddressDetails(address);
    const actualNetworkId = (0, mod_js_3.networkToId)(lucid.network);
    if (networkId !== actualNetworkId) {
        throw new Error(`Invalid address: Expected address with network id ${actualNetworkId}, but got ${networkId}`);
    }
    return type === "Byron"
        ? mod_js_1.C.ByronAddress.from_base58(address).to_address()
        : mod_js_1.C.Address.from_bech32(address);
}
