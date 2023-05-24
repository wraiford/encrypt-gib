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
         * todo: move this into args (args type)
         */
        let maxPassLength: number = 1000;
        /**
         * Number of passes within a pass section.
         *
         * todo: move this into args (args type)
         */
        let numOfPasses: number = 3;

        /** index into the `hexEncodedData` that we're working with */
        let indexHexEncodedData: number = 0;
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
        let indexHexEncodedDataAtStartOfPass = 0;
        for (let indexSection = 0; indexSection < passSections; indexSection++) {

            // adjust the passLength if it's the final one which might be shorter
            const isFinalPassSection = indexSection === passSections - 1;
            if (isFinalPassSection) { passLength = finalPassLength; }

            const resGetAlphabet = await getAlphabetsThisSection({
                passLength,
                indexHexEncodedDataAtStartOfPass,
                numOfPasses,
                hexEncodedData,
                recursionsPerHash,
                salt,
                saltStrategy,
                prevHash,
                hashAlgorithm,
            });

            let alphabetsThisSection = resGetAlphabet.alphabetsThisSection;
            prevHash = resGetAlphabet.prevHash;

            const encryptedIndexesThisSection = await getEncryptedIndexesThisSection({
                alphabetsThisSection,
                passLength,
                indexHexEncodedDataAtStartOfPass,
                hexEncodedData,
            });



            for (let indexThisPass = 0; indexThisPass < passLength; indexThisPass++) {
                indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexThisPass;
                const hexCharFromData: string = hexEncodedData[indexHexEncodedData];
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

async function getAlphabetsThisSection({
    passLength,
    numOfPasses,
    indexHexEncodedDataAtStartOfPass,
    hexEncodedData,
    recursionsPerHash,
    salt,
    saltStrategy,
    prevHash,
    hashAlgorithm,
}: {
    /** size of the pass, i.e. number of characters to process */
    passLength: number,
    /** number of times to iterate over the pass section */
    numOfPasses: number,
    indexHexEncodedDataAtStartOfPass: number,
    hexEncodedData: string,
    recursionsPerHash: number,
    salt: string,
    saltStrategy: SaltStrategy,
    prevHash: string,
    hashAlgorithm: HashAlgorithm,
}): Promise<{ alphabetsThisSection: string[], prevHash: string }> {
    const lc = `[${getAlphabetsThisSection.name}]`;
    try {
        /**
         * one alphabet per plaintext character (hex only atow).
         *
         * index into this is index in this pass (`indexPass`).
         *
         * Instead of building each plaintext character's alphabet until at
         * least one instance of that character is found, we will build up
         * each of the alphabets for the entire pass. Then we will add on to
         * those alphabets, depending on if the character is found (and once
         * I implement it, additionalSuperfluousAlphabetExtensions).
         */
        let alphabetsThisSection: string[] = [];
        let indexHexEncodedData: number;
        let hash: string;
        // first construct all alphabets for this pass section using the
        // given number of passes. Note that zero or more of these alphabets
        // may NOT include the hex character to encode, but this will be
        // addressed in the next step.
        for (let passNum = 0; passNum < numOfPasses; passNum++) {
            for (let indexIntoPassSection = 0; indexIntoPassSection < passLength; indexIntoPassSection++) {
                indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoPassSection;
                let alphabet = alphabetsThisSection[indexIntoPassSection] ?? '';

                for (let j = 0; j < recursionsPerHash; j++) {
                    const preHash = getPreHash({ prevHash, salt, saltStrategy });
                    // console.log(`${lc} preHash: ${preHash}`);
                    hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
                    prevHash = hash;
                }
                alphabet += hash!;

                alphabetsThisSection[indexIntoPassSection] = alphabet;
            }
        }

        // at this point, each alphabet is the same size (numOfPasses * hash
        // size), but it's not guaranteed that each alphabet will contain the
        // plaintext character.  so go through and extend any alphabets that do
        // not yet contain the plaintext character
        for (let indexIntoPassSection = 0; indexIntoPassSection < passLength; indexIntoPassSection++) {
            indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoPassSection;
            const hexCharFromData: string = hexEncodedData[indexHexEncodedData];
            let alphabet = alphabetsThisSection[indexIntoPassSection];

            while (!alphabet.includes(hexCharFromData)) {
                // only executes if alphabet doesnt already contain hexChar
                for (let j = 0; j < recursionsPerHash; j++) {
                    const preHash = getPreHash({ prevHash, salt, saltStrategy });
                    // console.log(`${lc} preHash: ${preHash}`);
                    hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
                    prevHash = hash;
                }
                alphabet += hash!;
            }

            alphabetsThisSection[indexIntoPassSection] = alphabet;
        }

        // at this point, each alphabet is at least the minimum size and is
        // guaranteed to have at least once instance of the plaintext hexChar.
        return { alphabetsThisSection, prevHash };
    } catch (error) {
        console.error(`${lc} error: ${h.extractErrorMsg(error)}`);
        throw error;
    }
}

// const encryptedIndexesThisSection = await getEncryptedIndexesThisSection({
async function getEncryptedIndexesThisSection({
    alphabetsThisSection,
    passLength,
    indexHexEncodedDataAtStartOfPass,
    hexEncodedData,
}: {
    alphabetsThisSection: string[],
    passLength: number,
    indexHexEncodedDataAtStartOfPass: number,
    hexEncodedData: string,
}): Promise<number[]> {
    const lc = `[${getEncryptedIndexesThisSection.name}]`;
    try {

    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}
