import * as h from '@ibgib/helper-gib';

import * as c from './constants.mjs';
import {
    EncryptArgs, EncryptResult,
    DecryptArgs, DecryptResult,
    SALT_STRATEGIES, SaltStrategy, HashAlgorithm,
} from './types.mjs';
import { decodeHexStringToString, encodeStringToHexString } from './helper.mjs';

/**
 * Encrypts given `dataToEncrypt` using the secret and other
 * given algorithm parameters.
 *
 * NOTE: These parameters must be the same when the call to `decrypt` happens!
 *
 * {@link DecryptArgs}
 * {@link DecryptResult}
 *
 * @returns a `DecryptResult` info object with either `decryptedData` or a populated `errors` array.
 */
export async function encrypt({
    dataToEncrypt,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
    confirm,
}: EncryptArgs): Promise<EncryptResult> {
    // lc === logContext - I'll only note this here
    const lc = `[${encrypt.name}]`;
    try {
        const result =
            await encryptImpl({
                dataToEncrypt,
                initialRecursions,
                recursionsPerHash,
                salt,
                saltStrategy,
                secret,
                hashAlgorithm,
                encryptedDataDelimiter,
                confirm,
            });
        return result;
    } catch (error) {
        console.error(`${lc}${error.message}`);
        return {
            errors: [error],
            initialRecursions,
            recursionsPerHash,
            salt,
            saltStrategy,
            hashAlgorithm
        };
    }
}

/**
 * Does the actual encryption work.
 *
 * {@link encrypt}
 * {@link EncryptArgs}
 * {@link EncryptResult}
 *
 * @returns a `EncryptResult` info object
 */
async function encryptImpl({
    dataToEncrypt,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
    confirm,
}: EncryptArgs): Promise<EncryptResult> {
    const lc = `[${encryptImpl.name}]`;

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
    let encryptedData: string = await encryptFromHex({
        hexEncodedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        secret,
        hashAlgorithm,
        encryptedDataDelimiter,
    });

    if (confirm) {
        const resDecrypt = await decrypt({
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

/**
 * Does the actual encryption from hexEncodedData with the given params.
 *
 * @returns encryptedData
 */
async function encryptFromHex({
    hexEncodedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
}: {
    hexEncodedData: string,
    initialRecursions: number,
    recursionsPerHash: number,
    salt: string,
    saltStrategy: SaltStrategy,
    secret: string,
    hashAlgorithm: HashAlgorithm,
    encryptedDataDelimiter: string,
}): Promise<string> {
    const lc = `[${encryptFromHex.name}]`;

    try {
        // set up "prevHash" as a starting point
        let prevHash = await doInitialRecursions({
            secret,
            initialRecursions,
            salt,
            saltStrategy: saltStrategy!,
            hashAlgorithm: hashAlgorithm!,
        });
        // console.log(`${lc} first prevHash: ${prevHash}`);

        // we have our prevHash starting point, so now we can iterate through the data
        let encryptedDataIndexes = [];
        for (let i = 0; i < hexEncodedData.length; i++) {
            // this is the character of data that we want to map to an index into the generated alphabet
            const hexCharFromData: string = hexEncodedData[i];
            let alphabet: string = "";
            let hash: string;
            while (!alphabet.includes(hexCharFromData)) {
                // if (alphabet.length > 128) {
                //     console.log(`alphabet is extending past 128... alphabet.length: ${alphabet.length}`);
                // }
                // console.log(`${lc} doing iteration...`);
                for (let j = 0; j < recursionsPerHash; j++) {
                    const preHash = getPreHash({prevHash, salt, saltStrategy});
                    // console.log(`${lc} preHash: ${preHash}`);
                    hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
                    prevHash = hash;
                }
                alphabet += hash!;
                // console.log(`${lc} alphabet: ${alphabet}`); // debug
            }

            // we now have the alphabet, so find the index of hex character
            const charIndex = alphabet.indexOf(hexCharFromData);
            // console.log(`${lc} charIndex: ${charIndex}`);
            encryptedDataIndexes.push(charIndex);
        }

        const encryptedData = encryptedDataIndexes.join(encryptedDataDelimiter);
        return encryptedData;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
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
 * @returns a `DecryptResult` info object with either `decryptedData` or a populated `errors` array.
 */
export async function decrypt({
    encryptedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
}: DecryptArgs): Promise<DecryptResult> {
    const lc = `[${decrypt.name}]`;
    try {
        // console.log(`${lc} encryptedDataDelimiter: ${encryptedDataDelimiter}`);
        const result =
            await decryptImpl({
                encryptedData,
                initialRecursions,
                recursionsPerHash,
                salt,
                saltStrategy,
                secret,
                hashAlgorithm,
                encryptedDataDelimiter,
            });
        return result;
    } catch (error) {
        console.error(`${lc}${error.message}`);
        return {
            errors: [error],
            initialRecursions,
            recursionsPerHash,
            salt,
            saltStrategy,
            hashAlgorithm,
            encryptedDataDelimiter,
        };
    }
}

/**
 * Does the actual decryption work.
 *
 * {@link decrypt}
 * {@link DecryptArgs}
 * {@link DecryptResult}
 *
 * @returns a `DecryptResult` info object
 */
async function decryptImpl({
    encryptedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
}: DecryptArgs): Promise<DecryptResult> {
    const lc = `[${decryptImpl.name}]`;
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
    let hexEncodedData: string = await decryptToHex({
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


/**
 * Takes a given encryptedData, in the form of a delimited string
 * of indexes, and decrypts it back into encoded hex (not the original
 * unencrypted data!).
 *
 * it does this by iterating
 *
 * @returns unencrypted, but still encoded, hex string of the original unencrypted data
 */
async function decryptToHex({
    encryptedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
}: {
    encryptedData: string,
    initialRecursions: number,
    recursionsPerHash: number,
    salt: string,
    saltStrategy: SaltStrategy,
    secret: string,
    hashAlgorithm: HashAlgorithm,
    encryptedDataDelimiter: string,
}): Promise<string> {
    const lc = `[${decryptToHex.name}]`;

    try {
        // set up "prevHash" as a starting point
        let prevHash = await doInitialRecursions({
            secret,
            initialRecursions,
            salt,
            saltStrategy: saltStrategy!,
            hashAlgorithm: hashAlgorithm!,
        });
        // console.log(`${lc} first prevHash: ${prevHash}`);

        // we have our prevHash starting point, so now we can iterate through the data
        // console.log(`${lc} encryptedDataDelimiter: ${encryptedDataDelimiter}`);
        let encryptedDataIndexes: number[] =
            encryptedData.split(encryptedDataDelimiter).map((nString: string) => parseInt(nString));
        // console.log(`${lc} encryptedDataIndexes: ${encryptedDataIndexes.toString()}`);
        let decryptedDataArray: string[] = [];
        for (let i = 0; i < encryptedDataIndexes.length; i++) {
            // this is the index of the character of data that we want to get out of the alphabet map
            // but to generate the alphabet, we may need to do multiple hash iterations, depending
            // on how big the index is. So if we don't hit a '7' until the third hash, then we need to
            // keep building out the alphabet until that third hash.
            // HACK: I'm going to do this with a while loop instead of a for because I want to get it working first.

            let charIndex = encryptedDataIndexes[i];
            // console.log(`${lc} charIndex: ${charIndex}`);
            let alphabet: string = "";
            let hash: string;
            while (charIndex >= alphabet.length) {
                // console.log(`${lc} doing iteration...`);
                for (let j = 0; j < recursionsPerHash; j++) {
                    const preHash = getPreHash({prevHash, salt, saltStrategy});
                    // console.log(`${lc} preHash: ${preHash}`);
                    hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
                    prevHash = hash;
                }
                alphabet += hash!;
                // console.log(`${lc} alphabet: ${alphabet}`); // debug
            }

            // we now have the alphabet, so index into it to get the decrypted hex char
            let hexChar: string = alphabet[charIndex];
            decryptedDataArray.push(hexChar);
        }

        // console.log(`${lc} decryptedDataArray: ${decryptedDataArray.toString()}`);
        // reconstitute the decryptedHex
        const decryptedHex: string = decryptedDataArray.join('');
        // console.log(`${lc} decryptedHex: ${decryptedHex.toString()}`);
        return decryptedHex;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}

// #region shared functions

/**
 * Creates the first "alphabet" that we will index into.
 *
 * We have this separate, because the initialRecursions help us
 * chug on the secret.
 *
 * If the data's hex character is not in this alphabet, it will
 * be expanded just as any
 */
async function doInitialRecursions({
    secret,
    initialRecursions,
    salt,
    saltStrategy,
    hashAlgorithm,
}: {
    secret: string,
    initialRecursions: number,
    salt: string,
    saltStrategy: SaltStrategy,
    hashAlgorithm: HashAlgorithm,
}): Promise<string> {
    const lc = `[${doInitialRecursions.name}]`;
    try {
        let hash: string | undefined;
        for (let i = 0; i < initialRecursions; i++) {
            const preHash = getPreHash({secret, prevHash: hash, salt, saltStrategy});
            hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
        }
        if (!hash) { throw new Error(`hash was not created`); }
        return hash;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}

/**
 * Builds the string that we will hash to get the next hash alphabet.
 *
 * @example
 * if we're prepending every hash, and this is the initial hash,
 * then we'll return `salt + secret`.
 *
 * @returns the string we're going to hash to get the next alphabet
 */
function getPreHash({
    secret,
    prevHash,
    salt,
    saltStrategy,
}: {
    secret?: string,
    prevHash?: string,
    salt: string,
    saltStrategy: SaltStrategy,
}): string {
    if (!(prevHash || secret)) { throw new Error(`Either secret or prevHash is required, but both are falsy)`); }
    switch (saltStrategy) {
        case SaltStrategy.prependPerHash:
            return salt + (prevHash || secret)
        case SaltStrategy.appendPerHash:
            return (prevHash || secret) + salt;
        case SaltStrategy.initialPrepend:
            return prevHash ? prevHash : salt + secret;
        case SaltStrategy.initialAppend:
            return prevHash ? prevHash : secret + salt;
        default:
            throw new Error(`Unknown saltStrategy: ${saltStrategy}`);
    }
}

// #endregion

