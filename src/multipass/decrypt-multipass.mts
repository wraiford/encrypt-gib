import * as h from '@ibgib/helper-gib';

import * as c from '../constants.mjs';
import { decodeHexStringToString } from '../helper.mjs';
import { DecryptArgs, DecryptResult, HashAlgorithm, SALT_STRATEGIES } from "../types.mjs";
import { decryptToHex_multipass } from './decrypt-to-hex-multipass.mjs';

/**
 * Does the actual decryption work using shortCircuit mitigation strategies.
 *
 * {@link decrypt}
 * {@link DecryptArgs}
 * {@link DecryptResult}
 *
 * @returns a `DecryptResult` info object
 */
export async function decryptImpl_multipass({
    encryptedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
}: DecryptArgs): Promise<DecryptResult> {
    const lc = `[${decryptImpl_multipass.name}]`;
    // console.log(`${lc} encryptedDataDelimiter: ${encryptedDataDelimiter}`);

    const errors: string[] = [];
    const warnings: string[] = [];

    // #region set args defaults

    initialRecursions = initialRecursions || c.DEFAULT_INITIAL_RECURSIONS;
    recursionsPerHash = recursionsPerHash || c.DEFAULT_RECURSIONS_PER_HASH;
    saltStrategy = saltStrategy || c.DEFAULT_SALT_STRATEGY;
    hashAlgorithm = hashAlgorithm || c.DEFAULT_HASH_ALGORITHM;
    salt = salt || await h.getUUID(c.DEFAULT_GETUUID_SEEDSIZE);
    encryptedDataDelimiter = encryptedDataDelimiter || c.DEFAULT_ENCRYPTED_DATA_DELIMITER;

    // #endregion

    // #region args validation

    const lcv = `[validation]`;

    if (!initialRecursions || initialRecursions < 1) { const e = `${lcv} initialRecursions required, and greater than 0`; console.error(e); errors.push(e); }
    if (!recursionsPerHash || recursionsPerHash < 1) { const e = `${lcv} recursionsPerHash required, and greater than 0`; console.error(e); errors.push(e); }
    if (!encryptedData) { const e = `${lcv} encryptedData required`; console.error(e); errors.push(e); }
    if (!salt) { const e = `${lcv} salt required`; console.error(e); errors.push(e); }
    if (!saltStrategy) { const e = `${lcv} saltStrategy required`; console.error(e); errors.push(e); }
    if (!secret) { const e = `${lcv} secret required`; console.error(e); errors.push(e); }
    if (!encryptedDataDelimiter) { const e = `${lcv} encryptedDataDelimiter required`; console.error(e); errors.push(e); }

    // if (hashAlgorithm !== 'SHA-256') { const e = `${lcv} only SHA-256 implemented`; console.error(e); errors.push(e); }
    if (!Object.values(HashAlgorithm).includes(hashAlgorithm)) {
        const e = `${lcv} only ${Object.values(HashAlgorithm)} hash algorithms implemented`; console.error(e); errors.push(e);
    }

    if (saltStrategy && !SALT_STRATEGIES.includes(saltStrategy!)) {
        const e = `${lcv} unknown saltStrategy: ${saltStrategy}`; console.error(e); errors.push(e);
    }

    if (errors.length > 0) {
        return {
            errors,
            initialRecursions,
            recursionsPerHash,
            salt,
            saltStrategy,
            hashAlgorithm,
            encryptedDataDelimiter,
        }
    }

    // #endregion

    // decrypt from indices into hex
    // console.log(`${lc} encryptedData: ${encryptedData}`);
    let hexEncodedData: string = await decryptToHex_multipass({
        encryptedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        secret,
        hashAlgorithm,
        encryptedDataDelimiter,
    });

    // console.log(`${lc} hexEncodedData: ${hexEncodedData}`);
    // decode hex back into original data
    const decryptedData: string = await decodeHexStringToString(hexEncodedData);

    return {
        decryptedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        hashAlgorithm,
        encryptedDataDelimiter,
        warnings: warnings.length > 0 ? warnings : undefined,
    };
}
