import * as h from '@ibgib/helper-gib';
import * as c from './constants.mjs';

import {
    EncryptArgs, EncryptResult,
    DecryptArgs, DecryptResult,
} from './types.mjs';
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
 * @see {@link DecryptArgs}
 * @see {@link DecryptResult}
 *
 * @returns `EncryptResult` info object with either `dataToEncrypt` or a populated `errors` array.
 */
export async function encrypt(args: EncryptArgs): Promise<EncryptResult> {
    const lc = `[${encrypt.name}]`;
    try {
        // initial common validation
        if (!args) { throw new Error('args required (E: 22e58e03c78f4c27bf18295b8d2cdd3a)'); }
        if (!args.dataToEncrypt) { throw new Error(`dataToEncrypt required (E: 168c9076e5434c83ba81e3485ee6f3e4)`); }

        // common defaults
        args.salt = args.salt || await h.getUUID(c.DEFAULT_GETUUID_SEEDSIZE);
        args.saltStrategy = args.saltStrategy || c.DEFAULT_SALT_STRATEGY;
        args.hashAlgorithm = args.hashAlgorithm || c.DEFAULT_HASH_ALGORITHM;
        args.recursionsPerHash = args.recursionsPerHash || c.DEFAULT_RECURSIONS_PER_HASH;

        // route to appropriate implementor
        let result: EncryptResult;
        if (args.multipass) {
            result = await encryptImpl_multipass(args);
        } else {
            result = await encryptImpl_legacy(args);
        }

        // print out warnings/errors if necessary
        if ((result.errors ?? []).length > 0) { result.errors!.forEach(e => console.warn(`${lc} ${e}`)); }
        if ((result.warnings ?? []).length > 0) { result.warnings!.forEach(w => console.warn(`${lc} ${w}`)); }

        // we're done
        return result;
    } catch (error) {
        console.error(`${lc}${error.message}`);
        throw error;
        // const result = { ...args, errors: [error] };
        // delete (result as any).dataToEncrypt;
        // return result;
    }
}

/**
 * Decrypts given `encryptedData` using the secret and other
 * given algorithm parameters.
 *
 * NOTE: These parameters must be the same as what the `encrypt` call used!
 *
 * @see {@link DecryptArgs}
 * @see {@link DecryptResult}
 *
 * @returns `DecryptResult` info object with either `decryptedData` or a populated `errors` array.
 */
export async function decrypt(args: DecryptArgs): Promise<DecryptResult> {
    const lc = `[${decrypt.name}]`;
    try {
        // initial common validation
        if (!args) { throw new Error('args required (E: fcd9b4aad85c4deba5fe5fde0b9ecb30)'); }
        if (!args.encryptedData) { throw new Error(`encryptedData required (E: f879f612428b4283bae089acee929a58)`); }

        // common defaults
        args.salt = args.salt || await h.getUUID(c.DEFAULT_GETUUID_SEEDSIZE);
        args.saltStrategy = args.saltStrategy || c.DEFAULT_SALT_STRATEGY;
        args.hashAlgorithm = args.hashAlgorithm || c.DEFAULT_HASH_ALGORITHM;
        args.recursionsPerHash = args.recursionsPerHash || c.DEFAULT_RECURSIONS_PER_HASH;


        // route to appropriate implementor
        let result: DecryptResult;
        if (args.multipass) {
            result = await decryptImpl_multipass(args);
        } else {
            result = await decryptImpl_legacy(args);
        }

        // print out warnings/errors if necessary
        if ((result.warnings ?? []).length > 0) { result.warnings!.forEach(w => console.warn(`${lc} ${w}`)); }
        if ((result.errors ?? []).length > 0) { result.errors!.forEach(e => console.warn(`${lc} ${e}`)); }

        // we're done
        return result;
        // console.log(`${lc} encryptedDataDelimiter: ${encryptedDataDelimiter}`);
    } catch (error) {
        console.error(`${lc}${error.message}`);
        throw error;
        // const result = { ...args, errors: [error] };
        // delete (result as any).encryptedData;
        // return result;
    }
}
