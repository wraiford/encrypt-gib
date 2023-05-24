import * as h from '@ibgib/helper-gib';

import * as c from './constants.mjs';
import {
    EncryptArgs, EncryptResult,
    DecryptArgs, DecryptResult,
    SALT_STRATEGIES, SaltStrategy, HashAlgorithm,
    AlphabetIndexingMode,
    ALPHABET_INDEXING_MODES,
} from './types.mjs';
import { decodeHexStringToString, encodeStringToHexString } from './helper.mjs';
import { INTERNAL_MAGIC_DEFAULT_ADDITIONAL_PASSES_MIN_LENGTH } from './constants.mjs';
import { encryptImpl_multipass } from './multipass/encrypt-multipass.mjs';
import { encryptImpl_legacy } from './legacy/encrypt-legacy.mjs'
import { decryptImpl_legacy } from './legacy/decrypt-legacy.mjs';
import { decryptImpl_multipass } from './multipass/decrypt-multipass.mjs';

/**
 * Encrypts given `dataToEncrypt` using the secret and other
 * given algorithm parameters.
 *
 * NOTE: These parameters must be the same when the call to `decrypt` happens!
 *
 * {@link DecryptArgs}
 * {@link DecryptResult}
 *
 * @returns `EncryptResult` info object with either `dataToEncrypt` or a populated `errors` array.
 */
export async function encrypt(args: EncryptArgs): Promise<EncryptResult> {
    const lc = `[${encrypt.name}]`;
    try {
        // route to appropriate implementor
        console.warn(`${lc} incorrect routing for encryptImpl. just to get going atm (W: 929eac48a2aa4bda8174e892b8b73d94)`)
        if (args.indexingMode) {
            return await encryptImpl_multipass(args);
        } else {
            return await encryptImpl_legacy(args);
        }
    } catch (error) {
        console.error(`${lc}${error.message}`);
        const result = { ...args, errors: [error] };
        delete (result as any).dataToEncrypt;
        return result;
    }
}

/**
 * Decrypts given `encryptedData` using the secret and other
 * given algorithm parameters.
 *
 * NOTE: These parameters must be the same as what the `encrypt` call used!
 *
 * {@link DecryptArgs}
 * {@link DecryptResult}
 *
 * @returns `DecryptResult` info object with either `decryptedData` or a populated `errors` array.
 */
export async function decrypt(args: DecryptArgs): Promise<DecryptResult> {
    const lc = `[${decrypt.name}]`;
    try {
        console.warn(`${lc} incorrect routing for encryptImpl. just to get going atm (W: 929eac48a2aa4bda8174e892b8b73d94)`)
        if (args.indexingMode) {
            return await decryptImpl_multipass(args);
        } else {
            return await decryptImpl_legacy(args);
        }
        // console.log(`${lc} encryptedDataDelimiter: ${encryptedDataDelimiter}`);
    } catch (error) {
        console.error(`${lc}${error.message}`);
        const result = { ...args, errors: [error] };
        delete (result as any).encryptedData;
        return result;
    }
}
