import * as h from '@ibgib/helper-gib';

import * as c from '../constants.mjs';
import { decodeHexStringToString } from '../helper.mjs';
import { ALPHABET_INDEXING_MODES, DecryptArgs, DecryptResult, HashAlgorithm, SALT_STRATEGIES } from "../types.mjs";
import { decryptToHex_multipass } from './decrypt-to-hex-multipass.mjs';

/**
 * Does the actual decryption work using shortCircuit mitigation strategies.
 *
//  * {@link decrypt}
 * {@link DecryptArgs}
 * {@link DecryptResult}
 *
 * @returns a `DecryptResult` info object
 */
export async function decryptImpl_multipass(args: DecryptArgs): Promise<DecryptResult> {
    const lc = `[${decryptImpl_multipass.name}]`;
    let {
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
    } = args;

    const errors: string[] = [];
    const warnings: string[] = [];

    if (!multipass) { throw new Error(`(UNEXPECTED) multipass required. This should be truthy in order to get to this impl fn. (E: 306bce36afd64b7182ca2b46ac04a261)`); }

    // #region set args defaults

    initialRecursions = initialRecursions || c.DEFAULT_INITIAL_RECURSIONS;
    recursionsPerHash = recursionsPerHash || c.DEFAULT_RECURSIONS_PER_HASH;
    saltStrategy = saltStrategy || c.DEFAULT_SALT_STRATEGY;
    hashAlgorithm = hashAlgorithm || c.DEFAULT_HASH_ALGORITHM;
    salt = salt || await h.getUUID(c.DEFAULT_GETUUID_SEEDSIZE);
    encryptedDataDelimiter = encryptedDataDelimiter || c.DEFAULT_ENCRYPTED_DATA_DELIMITER;

    indexingMode = indexingMode || c.DEFAULT_ALPHABET_INDEXING_MODE_MULTIPASS;

    let { maxPassSectionLength, numOfPasses } = multipass;
    maxPassSectionLength = maxPassSectionLength || c.DEFAULT_ADDITIONAL_PASSES_INTERMEDIATE_SECRET_LENGTH
    numOfPasses = numOfPasses || c.DEFAULT_NUM_OF_PASSES;

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
    if (!indexingMode) { const e = `${lcv} indexingMode required (E: a6fe15f8ba414e21b5355d23e808b976)`; console.error(e); errors.push(e); }
    if (!ALPHABET_INDEXING_MODES.includes(indexingMode)) { const e = `${lcv} invalid indexingMode (${indexingMode}). Must be one of ${ALPHABET_INDEXING_MODES} (E: 17435268651444e0b7a594135635fc58)`; console.error(e); errors.push(e); }
    if (maxPassSectionLength < 1) { const e = `${lcv} maxPassSectionLength must be greater than 0 (E: 0870831aa86b4bfa939aeee9f252326a)`; console.error(e); errors.push(e); }
    if (numOfPasses < 1) { const e = `${lcv} numOfPasses must be greater than 0 (E: 691d3c3765584c6f8c9aba1ee378df00)`; console.error(e); errors.push(e); }

    // if (hashAlgorithm !== 'SHA-256') { const e = `${lcv} only SHA-256 implemented`; console.error(e); errors.push(e); }
    if (!Object.values(HashAlgorithm).includes(hashAlgorithm)) {
        const e = `${lcv} only ${Object.values(HashAlgorithm)} hash algorithms implemented`; console.error(e); errors.push(e);
    }

    if (saltStrategy && !SALT_STRATEGIES.includes(saltStrategy!)) {
        const e = `${lcv} unknown saltStrategy: ${saltStrategy}`; console.error(e); errors.push(e);
    }

    if (errors.length > 0) {
        let result = { ...args, errors: errors };
        delete (result as any).encryptedData;
        return result;
    }

    // #endregion args validation

    // decrypt from indices into hex
    let hexEncodedData: string = await decryptToHex_multipass({
        encryptedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        secret,
        hashAlgorithm,
        encryptedDataDelimiter,
        maxPassSectionLength,
        numOfPasses,
    });

    // decode hex back into original data
    const decryptedData: string = await decodeHexStringToString(hexEncodedData);

    const result: DecryptResult = {
        ...args,
        decryptedData,
        warnings: warnings.length > 0 ? warnings : undefined,
    };
    delete (result as any).encryptedData;
    return result;
}
