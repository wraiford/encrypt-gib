import * as h from '@ibgib/helper-gib';

import * as c from '../constants.mjs';
import { decodeHexStringToString, encodeStringToHexString } from '../helper.mjs';
import { ALPHABET_INDEXING_MODES, EncryptArgs, EncryptResult, HashAlgorithm, SALT_STRATEGIES } from "../types.mjs";
import { encryptFromHex_stream } from './encrypt-from-hex-stream.mjs';
import { decryptImpl_stream } from './decrypt-stream.mjs';

/**
 * Does the actual encryption work using the original "stream" streaming
 * encryption.
 *
 * {@link encrypt}
 * {@link EncryptArgs}
 * {@link EncryptResult}
 *
 * @returns a `EncryptResult` info object
 */
export async function encryptImpl_stream({
    dataToEncrypt,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
    confirm,
    indexingMode,
}: EncryptArgs): Promise<EncryptResult> {
    const lc = `[${encryptImpl_stream.name}]`;

    const errors: string[] = [];
    let warnings: string[] = [];

    // #region set args defaults

    if (!initialRecursions) {
        console.warn(`${lc} initial recursions required. defaulting to ${c.DEFAULT_INITIAL_RECURSIONS}`);
        initialRecursions = c.DEFAULT_INITIAL_RECURSIONS;
    }
    recursionsPerHash = recursionsPerHash || c.DEFAULT_RECURSIONS_PER_HASH;
    saltStrategy = saltStrategy || c.DEFAULT_SALT_STRATEGY;
    hashAlgorithm = hashAlgorithm || c.DEFAULT_HASH_ALGORITHM;
    salt = salt || await h.getUUID(c.DEFAULT_GETUUID_SEEDSIZE);
    encryptedDataDelimiter = encryptedDataDelimiter || c.DEFAULT_ENCRYPTED_DATA_DELIMITER;
    indexingMode = indexingMode || c.DEFAULT_ALPHABET_INDEXING_MODE_LEGACY;

    // #endregion

    // #region args validation

    const lcv = `[validation]`;

    if (!initialRecursions || initialRecursions < 1) { const e = `${lcv} initialRecursions required, and greater than 0`; console.error(e); errors.push(e); }
    if (!recursionsPerHash || recursionsPerHash < 1) { const e = `${lcv} recursionsPerHash required, and greater than 0`; console.error(e); errors.push(e); }
    if (!dataToEncrypt) { const e = `${lcv} dataToEncrypt required`; console.error(e); errors.push(e); }
    if (!salt) { const e = `${lcv} salt required`; console.error(e); errors.push(e); }
    if (!saltStrategy) { const e = `${lcv} saltStrategy required`; console.error(e); errors.push(e); }
    if (!secret) { const e = `${lcv} secret required`; console.error(e); errors.push(e); }
    if (!encryptedDataDelimiter) { const e = `${lcv} encryptedDataDelimiter required`; console.error(e); errors.push(e); }
    if (!ALPHABET_INDEXING_MODES.includes(indexingMode)) { const e = `${lcv} invalid indexingMode (${indexingMode}). Must be one of ${ALPHABET_INDEXING_MODES} (E: 5955c46755434982982823c97adcf076)`; console.error(e); errors.push(e); }


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

    // #region encode data to just hex (i.e. only have 0-9, a-f)

    // console.log(`${lc} hex encoding dataToEncrypt: ${dataToEncrypt}`);
    const hexEncodedData: string = await encodeStringToHexString(dataToEncrypt);
    if (confirm) {
        // confirm data can be converted back into the original data
        // console.log(`${lc} hex decoding back to check with dataToEncrypt: ${hexEncodedData}`);
        const confirmDecodedData = await decodeHexStringToString(hexEncodedData);
        // console.log(`${lc} checkDecodedData: ${confirmDecodedData}`);
        if (confirmDecodedData !== dataToEncrypt) {
            throw new Error(`decoding encoded hex failed for this data: The encoded hex did not reverse to the original data.`);
        }
    }

    // #endregion

    // #region encrypt hex

    // comma-delimited indexes string
    let encryptedData: string = await encryptFromHex_stream({
        hexEncodedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        secret,
        hashAlgorithm,
        encryptedDataDelimiter,
        indexingMode: 'indexOf',
    });

    if (confirm) {
        const resDecrypt = await decryptImpl_stream({
            encryptedData,
            initialRecursions,
            recursionsPerHash,
            salt,
            saltStrategy,
            secret,
            hashAlgorithm,
            encryptedDataDelimiter,
        });
        if ((resDecrypt.errors || []).length > 0) {
            return {
                errors: [`Confirm check found that decrypt had errors.`, ...resDecrypt.errors!],
                initialRecursions,
                recursionsPerHash,
                salt,
                saltStrategy,
                hashAlgorithm,
                encryptedDataDelimiter,
            };
        } else if (!resDecrypt.decryptedData) {
            throw new Error(`Confirm check call to decrypt produced falsy decryptedData`);
        } else if (resDecrypt.decryptedData !== dataToEncrypt) {
            // DO NOT LEAVE THIS IN PROD!!!
            // console.log(`resDecrypt.decryptedData: ${resDecrypt.decryptedData}`); // DO NOT LEAVE THIS IN PROD!!!
            // console.log(`dataToEncrypt: ${dataToEncrypt}`); // DO NOT LEAVE THIS IN PROD!!!
            // DO NOT LEAVE THIS IN PROD!!!
            throw new Error(`The ENCRYPTED data did not decrypt back to the original data.`);
        } else {
            // console.log(`${lc} decrypt confirmed.`);
        }
        if ((resDecrypt.warnings || []).length > 0) {
            warnings = warnings.concat([`Confirm check call to decrypt had warnings.`, ...resDecrypt.warnings!])
        }
    }

    // #endregion

    return {
        encryptedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        hashAlgorithm,
        encryptedDataDelimiter,
        warnings: warnings.length > 0 ? warnings : undefined,
    };
}
