import * as h from '@ibgib/helper-gib';

import { doInitialRecursions, getPreHash } from "../common/encrypt-decrypt-common.mjs";
import { AlphabetIndexingMode, HashAlgorithm, SaltStrategy } from "../types.mjs";

export async function encryptFromHex_multipass({
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
    const lc = `[${encryptFromHex_multipass.name}]`;

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
        console.log(`${lc} using getIndex (indexingMode: ${indexingMode})`);

        /**
         * Each pass builds up multiple hashes per character in that pass.
         *
         * So this setting affects how much memory is used, as well as security.
         * The higher the pass length, the more a brute force attack has to
         * calculate before determining if a secret guess is correct.
         *
         *  todo: move this into args
         */
        let maxPassLength: number = 1000;

        /** index into the `hexEncodedData` */
        let indexData: number = 0;
        /**
         * ultimate indexes that will be stored in output.
         *
         * The index into this array corresponds to the index into
         * `hexEncodedData` array (`indexData`).
         */
        let encryptedDataIndexes = [];

        // set the initial pass length.
        let passLength = maxPassLength;
        console.warn(`${lc} todo: off by one error check. should be resolved with data in === data out (encrypted/decrypted) (W: 44e9ad4eb2cf43b3bba636a02f0db084)`)
        if (passLength > hexEncodedData.length) { passLength = hexEncodedData.length; }
        console.warn(`${lc} hexEncodedData.length: ${hexEncodedData.length}, passLength: ${passLength} (W: 1529570c6b474ad1a24f3a4c5b7eceb0)`);

        /**
         * We are doing multiple passes, but possibly only on subsets of
         * hexEncodedData. This variable is the number of sections that we're
         * doing. The final section may be less than a full pass section.
         *
         * _note: I am avoiding the use of "block" since that is an overloaded term in cryptography._
         */
        let passSections = Math.ceil(hexEncodedData.length / passLength);
        /**
         * the final pass may be less than the pass length
         */
        let finalPassLength = (passSections * passLength) - hexEncodedData.length;
        /**
         * This will be adjusted after each pass
         */
        let indexStartOfPass = 0;
        for (let indexSection = 0; indexSection < passSections; indexSection++) {
            /**
             * index into this is index in this pass (`indexPass`).
             */
            const alphabetsThisSection: string[] = [];
            const isFinalPassSection = indexSection === passSections - 1;
            // let hexDataIndexOffset = indexSection *
            // iterate through plaintext
            for (let indexPass = 0; indexPass < passLength; indexPass++) {
                // let passSize =

            }

        }

        // adjust i

        // this is the character of data that we want to map to an index into the generated alphabet
        throw new Error('not impl (E: 5cf31095eb274d45b3d104490b055989)')
        let i = 12345; // THIS IS FLAT WRONG JUST TO COMPILE
        const hexCharFromData: string = hexEncodedData[i];
        let alphabet: string = "";
        let hash: string;
        while (!alphabet.includes(hexCharFromData)) {
            if (alphabet.length > 64) {
                console.log(`alphabet is extending past 64... alphabet.length: ${alphabet.length}`);
            }
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

        const encryptedData = encryptedDataIndexes.join(encryptedDataDelimiter);
        return encryptedData;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}
