import * as h from '@ibgib/helper-gib';

import * as c from '../constants.mjs';
import { decodeHexStringToString, encodeStringToHexString } from '../helper.mjs';
import { ALPHABET_INDEXING_MODES, EncryptArgs, EncryptResult, HashAlgorithm, SALT_STRATEGIES } from "../types.mjs";
import { encryptFromHex_multipass } from './encrypt-from-hex-multipass.mjs';
import { decryptImpl_multipass } from './decrypt-multipass.mjs';

/**
 * Does the actual encryption work using the original "legacy" streaming
 * encryption.
 *
 * {@link encrypt}
 * {@link EncryptArgs}
 * {@link EncryptResult}
 *
 * @returns a `EncryptResult` info object
 */
export async function encryptImpl_multipass(args: EncryptArgs): Promise<EncryptResult> {
    const lc = `[${encryptImpl_multipass.name}]`;

    let {
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
    } = args;

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
    indexingMode = indexingMode || c.DEFAULT_ALPHABET_INDEXING_MODE;

    // #endregion

    // #region args validation

    const lcv = `[validation]`;

    if (!initialRecursions || initialRecursions < 1) { const e = `${lcv} initialRecursions required, and greater than 0 (E: dd96a75f0c504f34b1f9f2f32e011c50)`; console.error(e); errors.push(e); }
    if (!recursionsPerHash || recursionsPerHash < 1) { const e = `${lcv} recursionsPerHash required, and greater than 0 (E: 64cf53e0bf9f4963be6b165ca4e6566d)`; console.error(e); errors.push(e); }
    if (!dataToEncrypt) { const e = `${lcv} dataToEncrypt required (E: 168c9076e5434c83ba81e3485ee6f3e4)`; console.error(e); errors.push(e); }
    if (!salt) { const e = `${lcv} salt required (E: 136a5d237e0f4b1d89f8c87ac12a1507)`; console.error(e); errors.push(e); }
    if (!saltStrategy) { const e = `${lcv} saltStrategy required (E: 457ed117bf224b9f86fe81ab6bc35381)`; console.error(e); errors.push(e); }
    if (!secret) { const e = `${lcv} secret required (E: 5c363255055a45cfb07656e2f4854ed7)`; console.error(e); errors.push(e); }
    if (!encryptedDataDelimiter) { const e = `${lcv} encryptedDataDelimiter required (E: 1bbeb4dce19e4ac2bbe7d1e373739298)`; console.error(e); errors.push(e); }
    if (!indexingMode) { const e = `${lcv} indexingMode required (E: 693ebd2be64a438aa3b075d0cb0d92bf)`; console.error(e); errors.push(e); }
    if (!ALPHABET_INDEXING_MODES.includes(indexingMode)) { const e = `${lcv} invalid indexingMode (${indexingMode}). Must be one of ${ALPHABET_INDEXING_MODES} (E: 17435268651444e0b7a594135635fc58)`; console.error(e); errors.push(e); }

    // if (hashAlgorithm !== 'SHA-256') { const e = `${lcv} only SHA-256 implemented`; console.error(e); errors.push(e); }
    if (!Object.values(HashAlgorithm).includes(hashAlgorithm)) {
        const e = `${lcv} only ${Object.values(HashAlgorithm)} hash algorithms implemented`; console.error(e); errors.push(e);
    }

    if (saltStrategy && !SALT_STRATEGIES.includes(saltStrategy!)) {
        const e = `${lcv} unknown saltStrategy: ${saltStrategy}`; console.error(e); errors.push(e);
    }

    if (errors.length > 0) {
        let result = { ...args, errors: errors };
        delete (result as any).dataToEncrypt;
        return result;
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

    // #endregion encode data to just hex (i.e. only have 0-9, a-f)

    // #region encrypt hex

    // comma-delimited indexes string
    const encryptedData: string = await encryptFromHex_multipass({
        hexEncodedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        secret,
        hashAlgorithm,
        encryptedDataDelimiter,
        indexingMode,
    });

    if (confirm) {
        try {
            const resDecrypt = await decryptImpl_multipass({
                encryptedData,
                initialRecursions,
                recursionsPerHash,
                salt,
                saltStrategy,
                secret,
                hashAlgorithm,
                encryptedDataDelimiter,
                indexingMode,
            });
            if (!resDecrypt.decryptedData) {
                throw new Error(`Confirm check call to decrypt produced falsy decryptedData (E: a4fe82dee61f497e9dea188ea9c287a4)`);
            } else if (resDecrypt.decryptedData !== dataToEncrypt) {
                // DO NOT LEAVE THIS IN PROD!!!
                // console.log(`resDecrypt.decryptedData: ${resDecrypt.decryptedData}`); // DO NOT LEAVE THIS IN PROD!!!
                // console.log(`dataToEncrypt: ${dataToEncrypt}`); // DO NOT LEAVE THIS IN PROD!!!
                // DO NOT LEAVE THIS IN PROD!!!
                throw new Error(`The ENCRYPTED data did not decrypt back to the original data. (E: 16b5f1a11e4f438ab38a7f124178a7b8)`);
            } else {
                // console.log(`${lc} decrypt confirmed.`);
            }
            if ((resDecrypt.warnings || []).length > 0) {
                warnings = warnings.concat([`Confirm check call to decrypt had warnings.`, ...resDecrypt.warnings!])
            }
        } catch (error) {
            throw new Error(`${lc} confirm failed. decrypt error: ${h.extractErrorMsg(error)} (E: 782a84d9dc294ce9a6a325e3ab293adf)`);
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
