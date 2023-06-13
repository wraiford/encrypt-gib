import * as h from '@ibgib/helper-gib';

import { doInitialRecursions, getPreHash } from "../common/encrypt-decrypt-common.mjs";
import { AlphabetIndexingMode, HashAlgorithm, SaltStrategy } from "../types.mjs";
import { ENCRYPT_LOG_A_LOT } from '../constants.mjs';

// const logalot = ENCRYPT_LOG_A_LOT || true;

/**
 * Internal function that performs the encryption part of the overall `encrypt`
 * function when using the `multipass` option.
 *
 * @returns ciphertext string
 */
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
    maxPassSectionLength,
    numOfPasses,
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
    maxPassSectionLength: number,
    numOfPasses: number,
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
        // console.warn(`${lc} first prevHash: ${prevHash}`);
        // if (logalot) { console.warn(`${lc} doInitialRecursions result prevHash: ${prevHash} (W: 0a7979f8f0c6193e7a68d9573143e423)`); }

        /**
         * closure for avoiding checking `indexingMode` in a tight loop.
         *
         * usually I don't go for early optimization but this is low hanging
         * fruit in a very tight loop.
         */
        const getIndexOfCharInAlphabet: (alphabet: string, hexChar: string) => number =
            indexingMode === 'indexOf' ?
                (alphabet: string, hexChar: string) => { return alphabet.indexOf(hexChar) } :
                (alphabet: string, hexChar: string) => { return alphabet.lastIndexOf(hexChar) };
        // if (logalot) { console.warn(`${lc} using getIndexOfCharInAlphabet (indexingMode: ${indexingMode})`); }

        /**
         * ultimate indexes that will be stored in output.
         *
         * The index into this array corresponds to the index into
         * `hexEncodedData` array (`indexData`).
         */
        let encryptedDataIndexes: number[] = [];

        // set the initial pass length.
        let totalLength = hexEncodedData.length;
        let passSectionLength = maxPassSectionLength;
        if (passSectionLength > totalLength) { passSectionLength = totalLength; }
        // if (logalot) { console.warn(`${lc} totalLength (hexEncodedData.length): ${totalLength}, passSectionLength: ${passSectionLength} (W: 1529570c6b474ad1a24f3a4c5b7eceb0)`); }

        /**
         * We are doing multiple passes, but possibly only on subsets of
         * hexEncodedData. This variable is the number of sections that we're
         * doing. The final section may be less than a full pass section.
         *
         * _note: I am avoiding the use of "block" since that is an overloaded term in cryptography._
         */
        let passSections = Math.ceil(totalLength / passSectionLength);
        // if (logalot) { console.warn(`${lc} passSections: ${passSections}`); }
        /**
         * the final pass may be less than the pass length.
         */
        // let finalPassSectionLength = (passSectionLength - ((passSections * passSectionLength) - totalLength)) || passSectionLength; // if 0, then the last pass is full length
        let finalPassSectionLength = (totalLength % passSectionLength) || passSectionLength; // if 0, then the last pass is full length
        // if (logalot) { console.warn(`${lc} finalPassSectionLength: ${finalPassSectionLength}`); }
        /**
         * index into hexEncodedData at the start of each pass.
         *
         * This will be adjusted after each pass in the loop in preparation for
         * next iteration.
         */
        let indexHexEncodedDataAtStartOfPass = 0;

        // iterate through each pass "section" and create the alphabets for the
        // entire section. once the alphabets are created, iterate the plaintext
        // hexEncodedData and map them to the indices into those alphabets.
        // todo: add parameterized step to encode indices into characters?
        for (let indexSection = 0; indexSection < passSections; indexSection++) {

            // adjust the passSectionLength if it's the final one which might be shorter
            const isFinalPassSection = indexSection === passSections - 1;
            if (isFinalPassSection) { passSectionLength = finalPassSectionLength; }
            // if (logalot) { console.warn(`${lc} passSectionLength: ${passSectionLength}`); }

            const resGetAlphabets = await getAlphabetsThisSection({
                passSectionLength,
                indexHexEncodedDataAtStartOfPass,
                numOfPasses,
                hexEncodedData,
                recursionsPerHash,
                salt,
                saltStrategy,
                prevHash,
                hashAlgorithm,
            });

            let alphabetsThisSection = resGetAlphabets.alphabetsThisSection;
            // if (logalot) { console.warn(`${lc} alphabetsThisSection: ${h.pretty(alphabetsThisSection)} (W: 8c37818b9658d4c6a418b62ec38bd923)`); }
            prevHash = resGetAlphabets.prevHash;
            // if (logalot) { console.warn(`${lc} prevHash after alphabets created: ${prevHash} (W: 0b2ffc3ba7a19ecba74fcec8788a6c23)`); }

            const encryptedIndexesThisSection = await getEncryptedIndexesThisSection({
                alphabetsThisSection,
                passSectionLength,
                indexHexEncodedDataAtStartOfPass,
                hexEncodedData,
                numOfPasses,
                getIndexOfCharInAlphabet,
            });

            // if (logalot) { console.warn(`${lc} encryptedIndexesThisSection: ${encryptedIndexesThisSection} (W: f84c9d05e4160241664051b946ad3f23)`); }

            // if (logalot) { console.warn(`${lc} info before add to encryptedDataIndexes info: ${h.pretty({ indexSection, isFinalPassSection, passSectionLength, prevHash, encryptedDataIndexes, encryptedIndexesThisSection })}`); }
            encryptedDataIndexes = encryptedDataIndexes.concat(encryptedIndexesThisSection);
            // if (logalot) { console.warn(`${lc} encryptedDataIndexes so far: ${encryptedDataIndexes} (W: 58f9bbabce8eeb90a213ab1fa0d88123)`); }

            indexHexEncodedDataAtStartOfPass += passSectionLength;
        }

        // we now have populated encryptedDataIndexes fully.
        const resEncryptedData = encryptedDataIndexes.join(encryptedDataDelimiter);
        // if (logalot) { console.warn(`${lc} final resEncryptedData: ${resEncryptedData} (W: 681bf4eccdf6cddf675ee608804a7e23)`); }
        // console.warn(`${lc} resEncryptedData: ${resEncryptedData}`);
        return resEncryptedData;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}

async function getAlphabetsThisSection({
    passSectionLength,
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
    passSectionLength: number,
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
        // if (logalot) { console.warn(`${lc} info: ${h.pretty({ passSectionLength, numOfPasses, indexHexEncodedDataAtStartOfPass, prevHash })}`); }
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
        /** index into the `hexEncodedData` that we're working with */
        let indexHexEncodedData: number;
        let hash: string;
        // first construct all alphabets for this pass section using the
        // given number of passes. Note that zero or more of these alphabets
        // may NOT include the hex character to encode, but this will be
        // addressed in the next step.
        for (let passNum = 0; passNum < numOfPasses; passNum++) {
            for (let indexIntoPassSection = 0; indexIntoPassSection < passSectionLength; indexIntoPassSection++) {
                indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoPassSection;
                // if (logalot) { console.warn(`${lc} passNum: ${passNum}, indexIntoPassSection: ${indexIntoPassSection} (W: 13d09af12647907d4497842616915223)`); }
                let alphabet = alphabetsThisSection[indexIntoPassSection] ?? '';

                // if (logalot) { console.warn(`${lc} starting alphabet: ${alphabet} (W: b5a3ba3203e679ac454a854c32846723)`); }
                for (let j = 0; j < recursionsPerHash; j++) {
                    const preHash = getPreHash({ prevHash, salt, saltStrategy });
                    // console.warn(`${lc} preHash: ${preHash}`);
                    hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
                    prevHash = hash;
                }
                alphabet += hash!;
                // if (logalot) { console.warn(`${lc} extended alphabet: ${alphabet} (W: c0228b716a324761b581d38a805d192b)`); }

                alphabetsThisSection[indexIntoPassSection] = alphabet;
                // if (logalot) { console.warn(`${lc} alphabetsThisSection: ${h.pretty(alphabetsThisSection)} (W: 1bef26a111a4df4a6d501d5a662dd223)`); }
            }
        }
        // if (logalot) { console.warn(`${lc} initial alphabetsThisSection (${alphabetsThisSection.length}): ${h.pretty(alphabetsThisSection)} (W: ce1f77a7065e45cfb12995f097f70af4)`); }

        // if (logalot) { console.warn(`${lc} at this point, each alphabet is the same size (numOfPasses * hash size), but it's not guaranteed that each alphabet will contain the plaintext character.  so go through and extend any alphabets that do not yet contain the plaintext character (I: c75085603497ea684865010dfd8a3b23)`); }

        // at this point, each alphabet is the same size (numOfPasses * hash
        // size), but it's not guaranteed that each alphabet will contain the
        // plaintext character.  so go through and extend any alphabets that do
        // not yet contain the plaintext character
        for (let indexIntoPassSection = 0; indexIntoPassSection < passSectionLength; indexIntoPassSection++) {
            indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoPassSection;
            const hexCharFromData: string = hexEncodedData[indexHexEncodedData];
            let alphabet = alphabetsThisSection[indexIntoPassSection];

            while (!alphabet.includes(hexCharFromData)) {
                // if (logalot) { console.warn(`${lc} alphabet (${alphabet}) has to be extended because it does not contain hexChar (${hexCharFromData}).  (W: a8040eb78f4d123cfa423de33a7f3b23)`); }
                // only executes if alphabet doesnt already contain hexChar
                for (let j = 0; j < recursionsPerHash; j++) {
                    const preHash = getPreHash({ prevHash, salt, saltStrategy });
                    // console.warn(`${lc} preHash: ${preHash}`);
                    hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
                    prevHash = hash;
                }
                alphabet += hash!;
            }

            alphabetsThisSection[indexIntoPassSection] = alphabet;
            // if (logalot) { console.warn(`${lc} alphabetsThisSection (length ${alphabetsThisSection.length}): ${h.pretty(alphabetsThisSection)} (W: a86e76aa398d7e4b44dbe0fbb79c1623)`); }
        }
        // if (logalot) { console.warn(`${lc} guaranteed alphabetsThisSection (${alphabetsThisSection.length}): ${h.pretty(alphabetsThisSection)} (W: 8d684c05b116467aa92e946b03160310)`); }

        // if (logalot) { console.warn(`${lc} at this point, each alphabet is at least the minimum size and is guaranteed to have at least once instance of the plaintext hexChar. (W: c6f31445402b1c561670a2dd59530523)`); }
        // at this point, each alphabet is at least the minimum size and is
        // guaranteed to have at least once instance of the plaintext hexChar.
        // if (logalot) { console.warn(`${lc} return prevHash: ${prevHash}`) }
        return { alphabetsThisSection, prevHash };
    } catch (error) {
        console.error(`${lc} error: ${h.extractErrorMsg(error)}`);
        throw error;
    }
}

// const encryptedIndexesThisSection = await getEncryptedIndexesThisSection({
async function getEncryptedIndexesThisSection({
    alphabetsThisSection,
    passSectionLength,
    indexHexEncodedDataAtStartOfPass,
    hexEncodedData,
    numOfPasses,
    getIndexOfCharInAlphabet,
}: {
    alphabetsThisSection: string[],
    passSectionLength: number,
    indexHexEncodedDataAtStartOfPass: number,
    hexEncodedData: string,
    numOfPasses: number,
    getIndexOfCharInAlphabet: (alphabet: string, hexChar: string) => number,
}): Promise<number[]> {
    const lc = `[${getEncryptedIndexesThisSection.name}]`;
    try {
        const resIndexes: number[] = [];
        for (let indexIntoPassSection = 0; indexIntoPassSection < passSectionLength; indexIntoPassSection++) {
            const indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoPassSection;
            const alphabet = alphabetsThisSection[indexIntoPassSection];
            const encryptedIndexIntoAlphabet = getIndexOfCharInAlphabet(alphabet, hexEncodedData[indexHexEncodedData]);
            resIndexes.push(encryptedIndexIntoAlphabet);
        }

        return resIndexes;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}
