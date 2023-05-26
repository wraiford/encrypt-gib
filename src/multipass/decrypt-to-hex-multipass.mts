import * as h from '@ibgib/helper-gib';

import { doInitialRecursions, getPreHash } from "../common/encrypt-decrypt-common.mjs";
import { AlphabetIndexingMode, HashAlgorithm, SaltStrategy } from "../types.mjs";

/**
 * Takes a given encryptedData, in the form of a delimited string
 * of indexes, and decrypts it back into encoded hex (not the original
 * unencrypted data!).
 *
 * it does this by iterating
 *
 * @returns unencrypted, but still encoded, hex string of the original unencrypted data
 */
export async function decryptToHex_multipass({
    encryptedData,
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
    encryptedData: string,
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
    const lc = `[${decryptToHex_multipass.name}]`;

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

        // const getIndex: (alphabet: string, hexChar: string) => number =
        //     indexingMode === 'indexOf' ?
        //         (alphabet: string, hexChar: string) => { return alphabet.indexOf(hexChar) } :
        //         (alphabet: string, hexChar: string) => { return alphabet.lastIndexOf(hexChar) };

        // we have our prevHash starting point, so now we can iterate through the data
        // console.log(`${lc} encryptedDataDelimiter: ${encryptedDataDelimiter}`);
        let encryptedDataIndexes: number[] =
            encryptedData.split(encryptedDataDelimiter).map((nString: string) => parseInt(nString));
        // console.log(`${lc} encryptedDataIndexes: ${encryptedDataIndexes.toString()}`);
        let decryptedDataArray: string[] = [];

        // re-play multipass building of alphabets. pass section by pass
        // section, first create the minimum number of alphabets in that pass
        // section. then iterate through each cipher index, extending individual
        // alphabets jit/on demand depending on the cipher index. maintain
        // reference to prevHash throughout.

        // set the initial pass length.
        let totalLength = encryptedDataIndexes.length;
        let passSectionLength = maxPassSectionLength;
        console.warn(`${lc} todo: off by one error check. should be resolved with data in === data out (encrypted/decrypted) (W: e44e44b5bea6418f82745389a89bec33)`)
        if (passSectionLength > totalLength) { passSectionLength = totalLength; }
        console.warn(`${lc} totalLength (encryptedDataIndexes.length): ${totalLength}, passSectionLength: ${passSectionLength} (W: 5241a4133f5e4e3faafe42595100474e)`);

        /**
         * We are doing multiple passes, but possibly only on subsets of
         * encryptedDataIndexes. This variable is the number of sections that we're
         * doing. The final section may be less than a full pass section.
         *
         * _note: I am avoiding the use of "block" since that is an overloaded term in cryptography._
         */
        let passSections = Math.ceil(totalLength / passSectionLength);
        console.warn(`${lc} passSections: ${passSections}`);
        /**
         * the final pass may be less than the pass length.
         */
        // let finalPassSectionLength = (passSectionLength - ((passSections * passSectionLength) - totalLength)) || passSectionLength; // if 0, then the last pass is full length
        let finalPassSectionLength = (totalLength % passSectionLength) || passSectionLength; // if 0, then the last pass is full length
        console.warn(`${lc} finalPassSectionLength: ${finalPassSectionLength}`);
        /**
         * index into encryptedDataIndexes at the start of each pass.
         *
         * This will be adjusted after each pass in the loop in preparation for
         * next iteration.
         */
        let indexEncryptedDataIndexesAtStartOfPass = 0;

        // iterate through each pass "section" and create the alphabets for the
        // entire section. once the alphabets are created, iterate the plaintext
        // hexEncodedData and map them to the indices into those alphabets.
        // todo: add parameterized step to encode indices into characters?
        for (let indexSection = 0; indexSection < passSections; indexSection++) {

            // adjust the passSectionLength if it's the final one which might be shorter
            const isFinalPassSection = indexSection === passSections - 1;
            if (isFinalPassSection) { passSectionLength = finalPassSectionLength; }

            const resGetAlphabets = await getAlphabetsThisSection({
                passSectionLength,
                indexEncryptedDataIndexesAtStartOfPass,
                numOfPasses,
                encryptedDataIndexes,
                recursionsPerHash,
                salt,
                saltStrategy,
                prevHash,
                hashAlgorithm,
            });

            let alphabetsThisSection = resGetAlphabets.alphabetsThisSection;
            prevHash = resGetAlphabets.prevHash;

            const decryptedDataArrayThisSection = await getDecryptedDataArrayThisSection({
                alphabetsThisSection,
                passSectionLength,
                indexEncryptedDataIndexesAtStartOfPass,
                encryptedDataIndexes,
            });

            // console.warn(`${lc} info before add to encryptedDataIndexes info: ${h.pretty({ indexSection, isFinalPassSection, passSectionLength, prevHash, encryptedDataIndexes, encryptedIndexesThisSection })}`);
            console.warn(`${lc} info before add to encryptedDataIndexes info: ${h.pretty({ indexSection, isFinalPassSection, passSectionLength, prevHash, decryptedDataArrayThisSection })}`);
            decryptedDataArray = decryptedDataArray.concat(decryptedDataArrayThisSection);

            indexEncryptedDataIndexesAtStartOfPass += passSectionLength;
        }
        // for (let i = 0; i < encryptedDataIndexes.length; i++) {
        //     // this is the index of the character of data that we want to get out of the alphabet map
        //     // but to generate the alphabet, we may need to do multiple hash iterations, depending
        //     // on how big the index is. So if we don't hit a '7' until the third hash, then we need to
        //     // keep building out the alphabet until that third hash.
        //     // HACK: I'm going to do this with a while loop instead of a for because I want to get it working first.

        //     let charIndex = encryptedDataIndexes[i];
        //     // console.log(`${lc} charIndex: ${charIndex}`);
        //     let alphabet: string = "";
        //     let hash: string;
        //     while (charIndex >= alphabet.length) {
        //         // console.log(`${lc} doing iteration...`);
        //         for (let j = 0; j < recursionsPerHash; j++) {
        //             const preHash = getPreHash({ prevHash, salt, saltStrategy });
        //             // console.log(`${lc} preHash: ${preHash}`);
        //             hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
        //             prevHash = hash;
        //         }
        //         alphabet += hash!;
        //         // console.log(`${lc} alphabet: ${alphabet}`); // debug
        //     }

        //     // we now have the alphabet, so index into it to get the decrypted hex char
        //     let hexChar: string = alphabet[charIndex];
        //     decryptedDataArray.push(hexChar);
        // }

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

async function getAlphabetsThisSection({
    passSectionLength,
    numOfPasses,
    indexEncryptedDataIndexesAtStartOfPass,
    encryptedDataIndexes,
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
    indexEncryptedDataIndexesAtStartOfPass: number,
    encryptedDataIndexes: number[],
    recursionsPerHash: number,
    salt: string,
    saltStrategy: SaltStrategy,
    prevHash: string,
    hashAlgorithm: HashAlgorithm,
}): Promise<{ alphabetsThisSection: string[], prevHash: string }> {
    const lc = `[${getAlphabetsThisSection.name}]`;
    try {
        console.warn(`${lc} info: ${h.pretty({ passSectionLength, numOfPasses, indexEncryptedDataIndexesAtStartOfPass, prevHash })}`);
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
        /** index into the `encryptedDataIndexes` that we're working with */
        let indexEncryptedDataIndexes: number;
        let hash: string;
        // first construct all alphabets for this pass section using the
        // given number of passes. Note that zero or more of these alphabets
        // may NOT include the hex character to encode, but this will be
        // addressed in the next step.
        for (let passNum = 0; passNum < numOfPasses; passNum++) {
            for (let indexIntoPassSection = 0; indexIntoPassSection < passSectionLength; indexIntoPassSection++) {
                indexEncryptedDataIndexes = indexEncryptedDataIndexesAtStartOfPass + indexIntoPassSection;
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
        console.warn(`${lc} initial alphabetsThisSection (${alphabetsThisSection.length}): ${h.pretty(alphabetsThisSection)}`);

        // at this point, each alphabet is the same size (numOfPasses * hash
        // size), but it's not guaranteed that each alphabet will contain the
        // plaintext character.  so go through and extend any alphabets that do
        // not yet contain the plaintext character
        for (let indexIntoPassSection = 0; indexIntoPassSection < passSectionLength; indexIntoPassSection++) {
            indexEncryptedDataIndexes = indexEncryptedDataIndexesAtStartOfPass + indexIntoPassSection;
            const encryptedIndex: number = encryptedDataIndexes[indexEncryptedDataIndexes];
            let alphabet = alphabetsThisSection[indexIntoPassSection];

            // while (!alphabet.includes(hexCharFromData)) {
            while (alphabet.at(encryptedIndex) === undefined) {
                // only executes if alphabet isn't long enough for index
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
        console.warn(`${lc} guaranteed alphabetsThisSection (${alphabetsThisSection.length}): ${h.pretty(alphabetsThisSection)}`);

        // at this point, each alphabet is at least the minimum size and is
        // guaranteed to have at least once instance of the plaintext hexChar.
        console.warn(`${lc} return prevHash: ${prevHash}`)
        return { alphabetsThisSection, prevHash };
    } catch (error) {
        console.error(`${lc} error: ${h.extractErrorMsg(error)}`);
        throw error;
    }
}

async function getDecryptedDataArrayThisSection({
    alphabetsThisSection,
    passSectionLength,
    indexEncryptedDataIndexesAtStartOfPass,
    encryptedDataIndexes,
}: {
    alphabetsThisSection: string[],
    passSectionLength: number,
    indexEncryptedDataIndexesAtStartOfPass: number,
    encryptedDataIndexes: number[],
}): Promise<string[]> {
    const lc = `[${getDecryptedDataArrayThisSection.name}]`;
    try {
        const resDataArray: string[] = [];

        for (let indexIntoPassSection = 0; indexIntoPassSection < passSectionLength; indexIntoPassSection++) {
            let indexEncryptedDataIndexes = indexEncryptedDataIndexesAtStartOfPass + indexIntoPassSection;
            const encryptedIndex: number = encryptedDataIndexes[indexEncryptedDataIndexes];
            let alphabet = alphabetsThisSection[indexIntoPassSection];
            let decryptedCharString = alphabet[encryptedIndex];
            resDataArray.push(decryptedCharString);
        }

        return resDataArray;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}
