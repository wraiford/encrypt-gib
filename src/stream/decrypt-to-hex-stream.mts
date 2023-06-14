import * as h from '@ibgib/helper-gib';

import { doInitialRecursions_keystretch, execRound_getNextHash, getPreHash } from "../common/encrypt-decrypt-common.mjs";
import { HashAlgorithm, SaltStrategy } from "../types.mjs";

/**
 * Takes a given encryptedData, in the form of a delimited string
 * of indexes, and decrypts it back into encoded hex (not the original
 * unencrypted data!).
 *
 * it does this by iterating
 *
 * @returns unencrypted, but still encoded, hex string of the original unencrypted data
 */
export async function decryptToHex_stream({
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
    const lc = `[${decryptToHex_stream.name}]`;

    try {
        // set up "prevHash" as a starting point, similar to key-stretching
        let prevHash = await doInitialRecursions_keystretch({
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
            // this is the index of the character of data that we want to get
            // out of the alphabet map but to generate the alphabet, we may need
            // to do multiple hash iterations, depending on how big the index
            // is. So if we don't hit a '7' until the third hash, then we need
            // to keep building out the alphabet until that third hash.

            // HACK: I'm going to do this with a while loop instead of a for
            // because I want to get it working first.

            let charIndex = encryptedDataIndexes[i];
            // console.log(`${lc} charIndex: ${charIndex}`);
            let alphabet: string = "";
            let hash: string;
            while (charIndex >= alphabet.length) {
                // console.log(`${lc} doing iteration...`);
                hash = await execRound_getNextHash({
                    count: recursionsPerHash,
                    prevHash, salt, saltStrategy, hashAlgorithm
                });
                alphabet += hash;
                prevHash = hash;
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
