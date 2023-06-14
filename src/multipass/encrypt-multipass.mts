import * as h from '@ibgib/helper-gib';

import { decodeHexStringToString, encodeStringToHexString } from '../helper.mjs';
import { ALPHABET_INDEXING_MODES, EncryptArgs, EncryptResult, HashAlgorithm, SALT_STRATEGIES } from "../types.mjs";
import { encryptFromHex_multipass } from './encrypt-from-hex-multipass.mjs';
import { decryptImpl_multipass } from './decrypt-multipass.mjs';
import {
    DEFAULT_ALPHABET_INDEXING_MODE_MULTIPASS,
    DEFAULT_ENCRYPTED_DATA_DELIMITER, DEFAULT_INITIAL_RECURSIONS,
    DEFAULT_MAX_PASS_SECTION_LENGTH, DEFAULT_NUM_OF_PASSES,
    ENCRYPT_LOG_A_LOT
} from '../constants.mjs';

// const logalot = ENCRYPT_LOG_A_LOT || true;

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
        multipass,
    } = args;

    const errors: string[] = [];
    let warnings: string[] = [];

    if (!multipass) { throw new Error(`(UNEXPECTED) multipass required. This should be truthy in order to get to this impl fn. (E: 1dcbfb18f3794803a2520a6a78e59ed5)`); }

    // #region set args defaults

    if (!initialRecursions) {
        console.warn(`${lc} initial recursions required. defaulting to ${DEFAULT_INITIAL_RECURSIONS}`);
        initialRecursions = DEFAULT_INITIAL_RECURSIONS;
    }
    encryptedDataDelimiter = encryptedDataDelimiter || DEFAULT_ENCRYPTED_DATA_DELIMITER;
    indexingMode = indexingMode || DEFAULT_ALPHABET_INDEXING_MODE_MULTIPASS;

    let { maxPassSectionLength, numOfPasses } = multipass;
    maxPassSectionLength = maxPassSectionLength || DEFAULT_MAX_PASS_SECTION_LENGTH;
    numOfPasses = numOfPasses || DEFAULT_NUM_OF_PASSES;

    // #endregion set args defaults

    // #region args validation

    const lcv = `[validation]`;

    if (!initialRecursions || initialRecursions < 1) { const e = `${lcv} initialRecursions required, and greater than 0 (E: dd96a75f0c504f34b1f9f2f32e011c50)`; console.error(e); errors.push(e); }
    if (!recursionsPerHash || recursionsPerHash < 1) { const e = `${lcv} recursionsPerHash required, and greater than 0 (E: 64cf53e0bf9f4963be6b165ca4e6566d)`; console.error(e); errors.push(e); }
    if (!salt) { const e = `${lcv} salt required (E: 136a5d237e0f4b1d89f8c87ac12a1507)`; console.error(e); errors.push(e); }
    if (!saltStrategy) { const e = `${lcv} saltStrategy required (E: 457ed117bf224b9f86fe81ab6bc35381)`; console.error(e); errors.push(e); }
    if (!secret) { const e = `${lcv} secret required (E: 5c363255055a45cfb07656e2f4854ed7)`; console.error(e); errors.push(e); }
    if (!encryptedDataDelimiter) { const e = `${lcv} encryptedDataDelimiter required (E: 1bbeb4dce19e4ac2bbe7d1e373739298)`; console.error(e); errors.push(e); }
    if (!indexingMode) { const e = `${lcv} indexingMode required (E: 693ebd2be64a438aa3b075d0cb0d92bf)`; console.error(e); errors.push(e); }
    if (!ALPHABET_INDEXING_MODES.includes(indexingMode)) { const e = `${lcv} invalid indexingMode (${indexingMode}). Must be one of ${ALPHABET_INDEXING_MODES} (E: 17435268651444e0b7a594135635fc58)`; console.error(e); errors.push(e); }
    if (maxPassSectionLength < 1) { const e = `${lcv} maxPassSectionLength must be greater than 0 (E: 9f268207ae274b958fb91855331be259)`; console.error(e); errors.push(e); }
    if (numOfPasses < 1) { const e = `${lcv} numOfPasses must be greater than 0 (E: c3bcab79bb024d65b84947806290a7d4)`; console.error(e); errors.push(e); }

    // if (hashAlgorithm !== 'SHA-256') { const e = `${lcv} only SHA-256 implemented`; console.error(e); errors.push(e); }
    if (!Object.values(HashAlgorithm).includes(hashAlgorithm!)) {
        const e = `${lcv} only ${Object.values(HashAlgorithm)} hash algorithms implemented`; console.error(e); errors.push(e);
    }

    if (saltStrategy && !SALT_STRATEGIES.includes(saltStrategy!)) {
        const e = `${lcv} unknown saltStrategy: ${saltStrategy}`; console.error(e); errors.push(e);
    }

    if (errors.length > 0) {
        let result = { ...args, errors: errors };
        delete (result as any).dataToEncrypt;
        delete (result as any).secret;
        return result;
    }

    // #endregion args validation

    // #region encode data to just hex (i.e. only have 0-9, a-f)

    // console.log(`${lc} hex encoding dataToEncrypt: ${dataToEncrypt}`);
    const hexEncodedData: string = await encodeStringToHexString(dataToEncrypt);
    if (confirm) {
        // confirm data can be converted back into the original data
        // console.log(`${lc} hex decoding back to check with dataToEncrypt: ${hexEncodedData}`);
        // if (logalot) { console.log(`${lc} hexEncodedData: ${hexEncodedData} (I: 5568ee9bad6bfaa6f266bc9c5b5fc423)`); }
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
        recursionsPerHash: recursionsPerHash!,
        salt,
        saltStrategy: saltStrategy!,
        secret,
        hashAlgorithm: hashAlgorithm!,
        encryptedDataDelimiter,
        indexingMode,
        maxPassSectionLength,
        numOfPasses,
    });

    // DO NOT LEAVE THIS IN PROD!!!
    // console.warn(`${lc} TAKE THIS OUT!! encryptedData: ${encryptedData}`); // DO NOT LEAVE THIS IN PROD!!!
    // DO NOT LEAVE THIS IN PROD!!!

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
                multipass,
            });
            if (!resDecrypt.decryptedData) {
                throw new Error(`Confirm check call to decrypt produced falsy decryptedData (E: a4fe82dee61f497e9dea188ea9c287a4)`);
            } else if (resDecrypt.decryptedData !== dataToEncrypt) {
                // DO NOT LEAVE THIS IN PROD!!!
                // console.warn(`resDecrypt.decryptedData: ${resDecrypt.decryptedData}`); // DO NOT LEAVE THIS IN PROD!!!
                // console.warn(`dataToEncrypt: ${dataToEncrypt}`); // DO NOT LEAVE THIS IN PROD!!!
                // DO NOT LEAVE THIS IN PROD!!!
                throw new Error(`The ENCRYPTED data did not decrypt back to the original data. (E: 16b5f1a11e4f438ab38a7f124178a7b8)`);
                // } else {
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

    const result: EncryptResult = {
        ...args,
        encryptedData,
        warnings: warnings.length > 0 ? warnings : undefined,
    };
    delete (result as any).dataToEncrypt;
    delete (result as any).secret;
    return result;
}
