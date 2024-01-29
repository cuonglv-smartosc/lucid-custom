"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.addAssets = exports.applyDoubleCborEncoding = exports.applyParamsToScript = exports.nativeScriptFromJson = exports.fromUnit = exports.toUnit = exports.fromLabel = exports.toLabel = exports.toPublicKey = exports.fromText = exports.toText = exports.toHex = exports.fromHex = exports.networkToId = exports.coreToUtxo = exports.utxoToCore = exports.toScriptRef = exports.fromScriptRef = exports.assetsToValue = exports.valueToAssets = exports.generateSeedPhrase = exports.generatePrivateKey = exports.stakeCredentialOf = exports.paymentCredentialOf = exports.getAddressDetails = exports.Utils = void 0;
const hex_js_1 = require("../../deps/deno.land/std@0.100.0/encoding/hex.js");
const mod_js_1 = require("../core/mod.js");
const bip39_js_1 = require("../misc/bip39.js");
const crc8_js_1 = require("../misc/crc8.js");
const time_js_1 = require("../plutus/time.js");
const data_js_1 = require("../plutus/data.js");
class Utils {
    constructor(lucid) {
        Object.defineProperty(this, "lucid", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.lucid = lucid;
    }
    validatorToAddress(validator, stakeCredential) {
        const validatorHash = this.validatorToScriptHash(validator);
        if (stakeCredential) {
            return mod_js_1.C.BaseAddress.new(networkToId(this.lucid.network), mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_hex(validatorHash)), stakeCredential.type === "Key"
                ? mod_js_1.C.StakeCredential.from_keyhash(mod_js_1.C.Ed25519KeyHash.from_hex(stakeCredential.hash))
                : mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_hex(stakeCredential.hash)))
                .to_address()
                .to_bech32(undefined);
        }
        else {
            return mod_js_1.C.EnterpriseAddress.new(networkToId(this.lucid.network), mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_hex(validatorHash)))
                .to_address()
                .to_bech32(undefined);
        }
    }
    credentialToAddress(paymentCredential, stakeCredential) {
        if (stakeCredential) {
            return mod_js_1.C.BaseAddress.new(networkToId(this.lucid.network), paymentCredential.type === "Key"
                ? mod_js_1.C.StakeCredential.from_keyhash(mod_js_1.C.Ed25519KeyHash.from_hex(paymentCredential.hash))
                : mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_hex(paymentCredential.hash)), stakeCredential.type === "Key"
                ? mod_js_1.C.StakeCredential.from_keyhash(mod_js_1.C.Ed25519KeyHash.from_hex(stakeCredential.hash))
                : mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_hex(stakeCredential.hash)))
                .to_address()
                .to_bech32(undefined);
        }
        else {
            return mod_js_1.C.EnterpriseAddress.new(networkToId(this.lucid.network), paymentCredential.type === "Key"
                ? mod_js_1.C.StakeCredential.from_keyhash(mod_js_1.C.Ed25519KeyHash.from_hex(paymentCredential.hash))
                : mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_hex(paymentCredential.hash)))
                .to_address()
                .to_bech32(undefined);
        }
    }
    validatorToRewardAddress(validator) {
        const validatorHash = this.validatorToScriptHash(validator);
        return mod_js_1.C.RewardAddress.new(networkToId(this.lucid.network), mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_hex(validatorHash)))
            .to_address()
            .to_bech32(undefined);
    }
    credentialToRewardAddress(stakeCredential) {
        return mod_js_1.C.RewardAddress.new(networkToId(this.lucid.network), stakeCredential.type === "Key"
            ? mod_js_1.C.StakeCredential.from_keyhash(mod_js_1.C.Ed25519KeyHash.from_hex(stakeCredential.hash))
            : mod_js_1.C.StakeCredential.from_scripthash(mod_js_1.C.ScriptHash.from_hex(stakeCredential.hash)))
            .to_address()
            .to_bech32(undefined);
    }
    validatorToScriptHash(validator) {
        switch (validator.type) {
            case "Native":
                return mod_js_1.C.NativeScript.from_bytes(fromHex(validator.script))
                    .hash(mod_js_1.C.ScriptHashNamespace.NativeScript)
                    .to_hex();
            case "PlutusV1":
                return mod_js_1.C.PlutusScript.from_bytes(fromHex(applyDoubleCborEncoding(validator.script)))
                    .hash(mod_js_1.C.ScriptHashNamespace.PlutusV1)
                    .to_hex();
            case "PlutusV2":
                return mod_js_1.C.PlutusScript.from_bytes(fromHex(applyDoubleCborEncoding(validator.script)))
                    .hash(mod_js_1.C.ScriptHashNamespace.PlutusV2)
                    .to_hex();
            default:
                throw new Error("No variant matched");
        }
    }
    mintingPolicyToId(mintingPolicy) {
        return this.validatorToScriptHash(mintingPolicy);
    }
    datumToHash(datum) {
        return mod_js_1.C.hash_plutus_data(mod_js_1.C.PlutusData.from_bytes(fromHex(datum))).to_hex();
    }
    scriptHashToCredential(scriptHash) {
        return {
            type: "Script",
            hash: scriptHash,
        };
    }
    keyHashToCredential(keyHash) {
        return {
            type: "Key",
            hash: keyHash,
        };
    }
    generatePrivateKey() {
        return generatePrivateKey();
    }
    generateSeedPhrase() {
        return generateSeedPhrase();
    }
    unixTimeToSlot(unixTime) {
        return (0, time_js_1.unixTimeToEnclosingSlot)(unixTime, time_js_1.SLOT_CONFIG_NETWORK[this.lucid.network]);
    }
    slotToUnixTime(slot) {
        return (0, time_js_1.slotToBeginUnixTime)(slot, time_js_1.SLOT_CONFIG_NETWORK[this.lucid.network]);
    }
    /** Address can be in Bech32 or Hex. */
    getAddressDetails(address) {
        return getAddressDetails(address);
    }
    /**
     * Convert a native script from Json to the Hex representation.
     * It follows this Json format: https://github.com/input-output-hk/cardano-node/blob/master/doc/reference/simple-scripts.md
     */
    nativeScriptFromJson(nativeScript) {
        return nativeScriptFromJson(nativeScript);
    }
    paymentCredentialOf(address) {
        return paymentCredentialOf(address);
    }
    stakeCredentialOf(rewardAddress) {
        return stakeCredentialOf(rewardAddress);
    }
}
exports.Utils = Utils;
function addressFromHexOrBech32(address) {
    try {
        return mod_js_1.C.Address.from_bytes(fromHex(address));
    }
    catch (_e) {
        try {
            return mod_js_1.C.Address.from_bech32(address);
        }
        catch (_e) {
            throw new Error("Could not deserialize address.");
        }
    }
}
/** Address can be in Bech32 or Hex. */
function getAddressDetails(address) {
    // Base Address
    try {
        const parsedAddress = mod_js_1.C.BaseAddress.from_address(addressFromHexOrBech32(address));
        const paymentCredential = parsedAddress.payment_cred().kind() === 0
            ? {
                type: "Key",
                hash: toHex(parsedAddress.payment_cred().to_keyhash().to_bytes()),
            }
            : {
                type: "Script",
                hash: toHex(parsedAddress.payment_cred().to_scripthash().to_bytes()),
            };
        const stakeCredential = parsedAddress.stake_cred().kind() === 0
            ? {
                type: "Key",
                hash: toHex(parsedAddress.stake_cred().to_keyhash().to_bytes()),
            }
            : {
                type: "Script",
                hash: toHex(parsedAddress.stake_cred().to_scripthash().to_bytes()),
            };
        return {
            type: "Base",
            networkId: parsedAddress.to_address().network_id(),
            address: {
                bech32: parsedAddress.to_address().to_bech32(undefined),
                hex: toHex(parsedAddress.to_address().to_bytes()),
            },
            paymentCredential,
            stakeCredential,
        };
    }
    catch (_e) { /* pass */ }
    // Enterprise Address
    try {
        const parsedAddress = mod_js_1.C.EnterpriseAddress.from_address(addressFromHexOrBech32(address));
        const paymentCredential = parsedAddress.payment_cred().kind() === 0
            ? {
                type: "Key",
                hash: toHex(parsedAddress.payment_cred().to_keyhash().to_bytes()),
            }
            : {
                type: "Script",
                hash: toHex(parsedAddress.payment_cred().to_scripthash().to_bytes()),
            };
        return {
            type: "Enterprise",
            networkId: parsedAddress.to_address().network_id(),
            address: {
                bech32: parsedAddress.to_address().to_bech32(undefined),
                hex: toHex(parsedAddress.to_address().to_bytes()),
            },
            paymentCredential,
        };
    }
    catch (_e) { /* pass */ }
    // Pointer Address
    try {
        const parsedAddress = mod_js_1.C.PointerAddress.from_address(addressFromHexOrBech32(address));
        const paymentCredential = parsedAddress.payment_cred().kind() === 0
            ? {
                type: "Key",
                hash: toHex(parsedAddress.payment_cred().to_keyhash().to_bytes()),
            }
            : {
                type: "Script",
                hash: toHex(parsedAddress.payment_cred().to_scripthash().to_bytes()),
            };
        return {
            type: "Pointer",
            networkId: parsedAddress.to_address().network_id(),
            address: {
                bech32: parsedAddress.to_address().to_bech32(undefined),
                hex: toHex(parsedAddress.to_address().to_bytes()),
            },
            paymentCredential,
        };
    }
    catch (_e) { /* pass */ }
    // Reward Address
    try {
        const parsedAddress = mod_js_1.C.RewardAddress.from_address(addressFromHexOrBech32(address));
        const stakeCredential = parsedAddress.payment_cred().kind() === 0
            ? {
                type: "Key",
                hash: toHex(parsedAddress.payment_cred().to_keyhash().to_bytes()),
            }
            : {
                type: "Script",
                hash: toHex(parsedAddress.payment_cred().to_scripthash().to_bytes()),
            };
        return {
            type: "Reward",
            networkId: parsedAddress.to_address().network_id(),
            address: {
                bech32: parsedAddress.to_address().to_bech32(undefined),
                hex: toHex(parsedAddress.to_address().to_bytes()),
            },
            stakeCredential,
        };
    }
    catch (_e) { /* pass */ }
    // Limited support for Byron addresses
    try {
        const parsedAddress = ((address) => {
            try {
                return mod_js_1.C.ByronAddress.from_bytes(fromHex(address));
            }
            catch (_e) {
                try {
                    return mod_js_1.C.ByronAddress.from_base58(address);
                }
                catch (_e) {
                    throw new Error("Could not deserialize address.");
                }
            }
        })(address);
        return {
            type: "Byron",
            networkId: parsedAddress.network_id(),
            address: {
                bech32: "",
                hex: toHex(parsedAddress.to_address().to_bytes()),
            },
        };
    }
    catch (_e) { /* pass */ }
    throw new Error("No address type matched for: " + address);
}
exports.getAddressDetails = getAddressDetails;
function paymentCredentialOf(address) {
    const { paymentCredential } = getAddressDetails(address);
    if (!paymentCredential) {
        throw new Error("The specified address does not contain a payment credential.");
    }
    return paymentCredential;
}
exports.paymentCredentialOf = paymentCredentialOf;
function stakeCredentialOf(rewardAddress) {
    const { stakeCredential } = getAddressDetails(rewardAddress);
    if (!stakeCredential) {
        throw new Error("The specified address does not contain a stake credential.");
    }
    return stakeCredential;
}
exports.stakeCredentialOf = stakeCredentialOf;
function generatePrivateKey() {
    return mod_js_1.C.PrivateKey.generate_ed25519().to_bech32();
}
exports.generatePrivateKey = generatePrivateKey;
function generateSeedPhrase() {
    return (0, bip39_js_1.generateMnemonic)(256);
}
exports.generateSeedPhrase = generateSeedPhrase;
function valueToAssets(value) {
    const assets = {};
    assets["lovelace"] = BigInt(value.coin().to_str());
    const ma = value.multiasset();
    if (ma) {
        const multiAssets = ma.keys();
        for (let j = 0; j < multiAssets.len(); j++) {
            const policy = multiAssets.get(j);
            const policyAssets = ma.get(policy);
            const assetNames = policyAssets.keys();
            for (let k = 0; k < assetNames.len(); k++) {
                const policyAsset = assetNames.get(k);
                const quantity = policyAssets.get(policyAsset);
                const unit = toHex(policy.to_bytes()) + toHex(policyAsset.name());
                assets[unit] = BigInt(quantity.to_str());
            }
        }
    }
    return assets;
}
exports.valueToAssets = valueToAssets;
function assetsToValue(assets) {
    const multiAsset = mod_js_1.C.MultiAsset.new();
    const lovelace = assets["lovelace"];
    const units = Object.keys(assets);
    const policies = Array.from(new Set(units
        .filter((unit) => unit !== "lovelace")
        .map((unit) => unit.slice(0, 56))));
    policies.forEach((policy) => {
        const policyUnits = units.filter((unit) => unit.slice(0, 56) === policy);
        const assetsValue = mod_js_1.C.Assets.new();
        policyUnits.forEach((unit) => {
            assetsValue.insert(mod_js_1.C.AssetName.new(fromHex(unit.slice(56))), mod_js_1.C.BigNum.from_str(assets[unit].toString()));
        });
        multiAsset.insert(mod_js_1.C.ScriptHash.from_bytes(fromHex(policy)), assetsValue);
    });
    const value = mod_js_1.C.Value.new(mod_js_1.C.BigNum.from_str(lovelace ? lovelace.toString() : "0"));
    if (units.length > 1 || !lovelace)
        value.set_multiasset(multiAsset);
    return value;
}
exports.assetsToValue = assetsToValue;
function fromScriptRef(scriptRef) {
    const kind = scriptRef.get().kind();
    switch (kind) {
        case 0:
            return {
                type: "Native",
                script: toHex(scriptRef.get().as_native().to_bytes()),
            };
        case 1:
            return {
                type: "PlutusV1",
                script: toHex(scriptRef.get().as_plutus_v1().to_bytes()),
            };
        case 2:
            return {
                type: "PlutusV2",
                script: toHex(scriptRef.get().as_plutus_v2().to_bytes()),
            };
        default:
            throw new Error("No variant matched.");
    }
}
exports.fromScriptRef = fromScriptRef;
function toScriptRef(script) {
    switch (script.type) {
        case "Native":
            return mod_js_1.C.ScriptRef.new(mod_js_1.C.Script.new_native(mod_js_1.C.NativeScript.from_bytes(fromHex(script.script))));
        case "PlutusV1":
            return mod_js_1.C.ScriptRef.new(mod_js_1.C.Script.new_plutus_v1(mod_js_1.C.PlutusScript.from_bytes(fromHex(applyDoubleCborEncoding(script.script)))));
        case "PlutusV2":
            return mod_js_1.C.ScriptRef.new(mod_js_1.C.Script.new_plutus_v2(mod_js_1.C.PlutusScript.from_bytes(fromHex(applyDoubleCborEncoding(script.script)))));
        default:
            throw new Error("No variant matched.");
    }
}
exports.toScriptRef = toScriptRef;
function utxoToCore(utxo) {
    const address = (() => {
        try {
            return mod_js_1.C.Address.from_bech32(utxo.address);
        }
        catch (_e) {
            return mod_js_1.C.ByronAddress.from_base58(utxo.address).to_address();
        }
    })();
    const output = mod_js_1.C.TransactionOutput.new(address, assetsToValue(utxo.assets));
    if (utxo.datumHash) {
        output.set_datum(mod_js_1.C.Datum.new_data_hash(mod_js_1.C.DataHash.from_bytes(fromHex(utxo.datumHash))));
    }
    // inline datum
    if (!utxo.datumHash && utxo.datum) {
        output.set_datum(mod_js_1.C.Datum.new_data(mod_js_1.C.Data.new(mod_js_1.C.PlutusData.from_bytes(fromHex(utxo.datum)))));
    }
    if (utxo.scriptRef) {
        output.set_script_ref(toScriptRef(utxo.scriptRef));
    }
    return mod_js_1.C.TransactionUnspentOutput.new(mod_js_1.C.TransactionInput.new(mod_js_1.C.TransactionHash.from_bytes(fromHex(utxo.txHash)), mod_js_1.C.BigNum.from_str(utxo.outputIndex.toString())), output);
}
exports.utxoToCore = utxoToCore;
function coreToUtxo(coreUtxo) {
    return {
        txHash: toHex(coreUtxo.input().transaction_id().to_bytes()),
        outputIndex: parseInt(coreUtxo.input().index().to_str()),
        assets: valueToAssets(coreUtxo.output().amount()),
        address: coreUtxo.output().address().as_byron()
            ? coreUtxo.output().address().as_byron()?.to_base58()
            : coreUtxo.output().address().to_bech32(undefined),
        datumHash: coreUtxo.output()?.datum()?.as_data_hash()?.to_hex(),
        datum: coreUtxo.output()?.datum()?.as_data() &&
            toHex(coreUtxo.output().datum().as_data().get().to_bytes()),
        scriptRef: coreUtxo.output()?.script_ref() &&
            fromScriptRef(coreUtxo.output().script_ref()),
    };
}
exports.coreToUtxo = coreToUtxo;
function networkToId(network) {
    switch (network) {
        case "Preview":
            return 0;
        case "Preprod":
            return 0;
        case "Custom":
            return 0;
        case "Mainnet":
            return 1;
        default:
            throw new Error("Network not found");
    }
}
exports.networkToId = networkToId;
function fromHex(hex) {
    return (0, hex_js_1.decodeString)(hex);
}
exports.fromHex = fromHex;
function toHex(bytes) {
    return (0, hex_js_1.encodeToString)(bytes);
}
exports.toHex = toHex;
/** Convert a Hex encoded string to a Utf-8 encoded string. */
function toText(hex) {
    return new TextDecoder().decode((0, hex_js_1.decode)(new TextEncoder().encode(hex)));
}
exports.toText = toText;
/** Convert a Utf-8 encoded string to a Hex encoded string. */
function fromText(text) {
    return toHex(new TextEncoder().encode(text));
}
exports.fromText = fromText;
function toPublicKey(privateKey) {
    return mod_js_1.C.PrivateKey.from_bech32(privateKey).to_public().to_bech32();
}
exports.toPublicKey = toPublicKey;
/** Padded number in Hex. */
function checksum(num) {
    return (0, crc8_js_1.crc8)(fromHex(num)).toString(16).padStart(2, "0");
}
function toLabel(num) {
    if (num < 0 || num > 65535) {
        throw new Error(`Label ${num} out of range: min label 1 - max label 65535.`);
    }
    const numHex = num.toString(16).padStart(4, "0");
    return "0" + numHex + checksum(numHex) + "0";
}
exports.toLabel = toLabel;
function fromLabel(label) {
    if (label.length !== 8 || !(label[0] === "0" && label[7] === "0")) {
        return null;
    }
    const numHex = label.slice(1, 5);
    const num = parseInt(numHex, 16);
    const check = label.slice(5, 7);
    return check === checksum(numHex) ? num : null;
}
exports.fromLabel = fromLabel;
/**
 * @param name Hex encoded
 */
function toUnit(policyId, name, label) {
    const hexLabel = Number.isInteger(label) ? toLabel(label) : "";
    const n = name ? name : "";
    if ((n + hexLabel).length > 64) {
        throw new Error("Asset name size exceeds 32 bytes.");
    }
    if (policyId.length !== 56) {
        throw new Error(`Policy id invalid: ${policyId}.`);
    }
    return policyId + hexLabel + n;
}
exports.toUnit = toUnit;
/**
 * Splits unit into policy id, asset name (entire asset name), name (asset name without label) and label if applicable.
 * name will be returned in Hex.
 */
function fromUnit(unit) {
    const policyId = unit.slice(0, 56);
    const assetName = unit.slice(56) || null;
    const label = fromLabel(unit.slice(56, 64));
    const name = (() => {
        const hexName = Number.isInteger(label) ? unit.slice(64) : unit.slice(56);
        return hexName || null;
    })();
    return { policyId, assetName, name, label };
}
exports.fromUnit = fromUnit;
/**
 * Convert a native script from Json to the Hex representation.
 * It follows this Json format: https://github.com/input-output-hk/cardano-node/blob/master/doc/reference/simple-scripts.md
 */
function nativeScriptFromJson(nativeScript) {
    return {
        type: "Native",
        script: toHex(mod_js_1.C.encode_json_str_to_native_script(JSON.stringify(nativeScript), "", mod_js_1.C.ScriptSchema.Node).to_bytes()),
    };
}
exports.nativeScriptFromJson = nativeScriptFromJson;
function applyParamsToScript(plutusScript, params, type) {
    const p = (type ? data_js_1.Data.castTo(params, type) : params);
    return toHex(mod_js_1.C.apply_params_to_plutus_script(mod_js_1.C.PlutusList.from_bytes(fromHex(data_js_1.Data.to(p))), mod_js_1.C.PlutusScript.from_bytes(fromHex(applyDoubleCborEncoding(plutusScript)))).to_bytes());
}
exports.applyParamsToScript = applyParamsToScript;
/** Returns double cbor encoded script. If script is already double cbor encoded it's returned as it is. */
function applyDoubleCborEncoding(script) {
    try {
        mod_js_1.C.PlutusScript.from_bytes(mod_js_1.C.PlutusScript.from_bytes(fromHex(script)).bytes());
        return script;
    }
    catch (_e) {
        return toHex(mod_js_1.C.PlutusScript.new(fromHex(script)).to_bytes());
    }
}
exports.applyDoubleCborEncoding = applyDoubleCborEncoding;
function addAssets(...assets) {
    return assets.reduce((a, b) => {
        for (const k in b) {
            if (Object.hasOwn(b, k)) {
                a[k] = (a[k] || 0n) + b[k];
            }
        }
        return a;
    }, {});
}
exports.addAssets = addAssets;
