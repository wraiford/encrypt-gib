import * as h from '@ibgib/helper-gib';

import { doInitialRecursions, getPreHash } from "../common/encrypt-decrypt-common.mjs";
import { AlphabetIndexingMode, HashAlgorithm, SaltStrategy } from "../types.mjs";

/**
 * Does the actual encryption from hexEncodedData with the given params.
 *
 * @returns encryptedData
 */
export async function encryptFromHex_legacy({
    hexEncodedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
    indexingMode,
}: {
    hexEncodedData: string,
    initialRecursions: number,
    recursionsPerHash: number,
    salt: string,
    saltStrategy: SaltStrategy,
    secret: string,
    hashAlgorithm: HashAlgorithm,
    encryptedDataDelimiter: string,
    indexingMode: AlphabetIndexingMode,
}): Promise<string> {
    const lc = `[${encryptFromHex_legacy.name}]`;

    try {
        // set up "prevHash" as a starting point, similar to key-stretching
        let prevHash = await doInitialRecursions({
            secret,
            initialRecursions,
            salt,
            saltStrategy: saltStrategy!,
            hashAlgorithm: hashAlgorithm!,
        });
        // console.log(`${lc} first prevHash: ${prevHash}`);

        const getIndex: (alphabet: string, hexChar: string) => number =
            indexingMode === 'indexOf' ?
                (alphabet: string, hexChar: string) => { return alphabet.indexOf(hexChar) } :
                (alphabet: string, hexChar: string) => { return alphabet.lastIndexOf(hexChar) };
        // console.log(`${lc} using getIndex (indexingMode: ${indexingMode})`);

        // we have our prevHash starting point, so now we can iterate through the data
        let encryptedDataIndexes = [];
        for (let i = 0; i < hexEncodedData.length; i++) {
            // this is the character of data that we want to map to an index into the generated alphabet
            const hexCharFromData: string = hexEncodedData[i];
            let alphabet: string = "";
            let hash: string;
            while (!alphabet.includes(hexCharFromData)) {
                // if (alphabet.length > 64) {
                //     console.log(`alphabet is extending past 64... alphabet.length: ${alphabet.length}`);
                // }
                // console.log(`${lc} doing iteration...`);
                for (let j = 0; j < recursionsPerHash; j++) {
                    const preHash = getPreHash({ prevHash, salt, saltStrategy });
                    // console.log(`${lc} preHash: ${preHash}`);
                    hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
                    prevHash = hash;
                }
                alphabet += hash!;
                // console.log(`${lc} alphabet: ${alphabet}`); // debug
            }

            // we now have the alphabet, so find the index of hex character
            // const charIndex = alphabet.indexOf(hexCharFromData);
            const charIndex = getIndex(alphabet, hexCharFromData);
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
