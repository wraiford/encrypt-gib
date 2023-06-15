import * as h from '@ibgib/helper-gib';

import { doInitialRecursions_keystretch, execRound_getNextHash, } from "../common/encrypt-decrypt-common.mjs";
import { AlphabetIndexingMode, HashAlgorithm, SaltStrategy } from "../types.mjs";

// import { ENCRYPT_LOG_A_LOT } from '../constants.mjs';
// const logalot = ENCRYPT_LOG_A_LOT || true;

/**
 * Internal function that performs the encryption part of the overall `encrypt`
 * function when using the `multipass` option.
 *
 * @returns ciphertext string
 */
export async function encryptFromHex_blockMode({
    hexEncodedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
    indexingMode,
    maxBlockSize,
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
    maxBlockSize: number,
    numOfPasses: number,
}): Promise<string> {
    const lc = `[${encryptFromHex_blockMode.name}]`;

    try {
        // set up "prevHash" as a starting point, similar to key-stretching
        let prevHash = await doInitialRecursions_keystretch({
            secret,
            initialRecursions,
            salt,
            saltStrategy: saltStrategy!,
            hashAlgorithm: hashAlgorithm!,
        });
        // console.warn(`${lc} first prevHash: ${prevHash}`);
        // if (logalot) { console.warn(`${lc} doInitialRecursions_keystretch result prevHash: ${prevHash} (W: 0a7979f8f0c6193e7a68d9573143e423)`); }

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
        let blockSize = maxBlockSize;
        if (blockSize > totalLength) { blockSize = totalLength; }
        // if (logalot) { console.warn(`${lc} totalLength (hexEncodedData.length): ${totalLength}, blockSize: ${blockSize} (W: 1529570c6b474ad1a24f3a4c5b7eceb0)`); }

        /**
         * We are doing multiple passes, but possibly only on subsets of
         * hexEncodedData. This variable is the number of sections that we're
         * doing. The final section may be less than a full pass section.
         *
         * _note: I am avoiding the use of "block" since that is an overloaded term in cryptography._
         */
        let blockSections = Math.ceil(totalLength / blockSize);
        // if (logalot) { console.warn(`${lc} blockSections: ${blockSections}`); }
        /**
         * the final pass may be less than the pass length.
         */
        // let finalBlockSize = (blockSize - ((blockSections * blockSize) - totalLength)) || blockSize; // if 0, then the last pass is full length
        let finalBlockSize = (totalLength % blockSize) || blockSize; // if 0, then the last pass is full length
        // if (logalot) { console.warn(`${lc} finalBlockSize: ${finalBlockSize}`); }
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
        for (let indexOfBlock = 0; indexOfBlock < blockSections; indexOfBlock++) {

            // adjust the blockSize if it's the final one which might be shorter
            const isFinalBlock = indexOfBlock === blockSections - 1;
            if (isFinalBlock) { blockSize = finalBlockSize; }
            // if (logalot) { console.warn(`${lc} blockSize: ${blockSize}`); }

            const resGetAlphabets = await getAlphabetsThisBlock({
                blockSize,
                indexHexEncodedDataAtStartOfPass,
                numOfPasses,
                hexEncodedData,
                recursionsPerHash,
                salt,
                saltStrategy,
                prevHash,
                hashAlgorithm,
            });

            let alphabetsThisBlock = resGetAlphabets.alphabetsThisBlock;
            // if (logalot) { console.warn(`${lc} alphabetsThisBlock: ${h.pretty(alphabetsThisBlock)} (W: 8c37818b9658d4c6a418b62ec38bd923)`); }
            prevHash = resGetAlphabets.prevHash;
            // if (logalot) { console.warn(`${lc} prevHash after alphabets created: ${prevHash} (W: 0b2ffc3ba7a19ecba74fcec8788a6c23)`); }

            const encryptedIndexesThisBlock = await getEncryptedIndexesThisBlock({
                alphabetsThisBlock,
                blockSize,
                indexHexEncodedDataAtStartOfPass,
                hexEncodedData,
                getIndexOfCharInAlphabet,
            });

            // if (logalot) { console.warn(`${lc} encryptedIndexesThisBlock: ${encryptedIndexesThisBlock} (W: f84c9d05e4160241664051b946ad3f23)`); }

            // if (logalot) { console.warn(`${lc} info before add to encryptedDataIndexes info: ${h.pretty({ indexOfBlock, isFinalBlock, blockSize, prevHash, encryptedDataIndexes, encryptedIndexesThisBlock })}`); }
            encryptedDataIndexes = encryptedDataIndexes.concat(encryptedIndexesThisBlock);
            // if (logalot) { console.warn(`${lc} encryptedDataIndexes so far: ${encryptedDataIndexes} (W: 58f9bbabce8eeb90a213ab1fa0d88123)`); }

            indexHexEncodedDataAtStartOfPass += blockSize;
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

async function getAlphabetsThisBlock({
    blockSize,
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
    blockSize: number,
    /** number of times to iterate over the pass section */
    numOfPasses: number,
    indexHexEncodedDataAtStartOfPass: number,
    hexEncodedData: string,
    recursionsPerHash: number,
    salt: string,
    saltStrategy: SaltStrategy,
    prevHash: string,
    hashAlgorithm: HashAlgorithm,
}): Promise<{ alphabetsThisBlock: string[], prevHash: string }> {
    const lc = `[${getAlphabetsThisBlock.name}]`;
    try {
        // if (logalot) { console.warn(`${lc} info: ${h.pretty({ blockSize, numOfPasses, indexHexEncodedDataAtStartOfPass, prevHash })}`); }
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
        let alphabetsThisBlock: string[] = [];
        /** index into the `hexEncodedData` that we're working with */
        let indexHexEncodedData: number;
        let hash: string;
        // first construct all alphabets for this pass section using the
        // given number of passes. Note that zero or more of these alphabets
        // may NOT include the hex character to encode, but this will be
        // addressed in the next step.
        for (let passNum = 0; passNum < numOfPasses; passNum++) {
            for (let indexIntoBlock = 0; indexIntoBlock < blockSize; indexIntoBlock++) {
                indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoBlock;
                // if (logalot) { console.warn(`${lc} passNum: ${passNum}, indexIntoBlock: ${indexIntoBlock} (W: 13d09af12647907d4497842616915223)`); }
                let alphabet = alphabetsThisBlock[indexIntoBlock] ?? '';

                // if (logalot) { console.warn(`${lc} starting alphabet: ${alphabet} (W: b5a3ba3203e679ac454a854c32846723)`); }
                hash = await execRound_getNextHash({
                    count: recursionsPerHash,
                    prevHash, salt, saltStrategy, hashAlgorithm
                });
                alphabet += hash;
                prevHash = hash;
                // if (logalot) { console.warn(`${lc} extended alphabet: ${alphabet} (W: c0228b716a324761b581d38a805d192b)`); }

                alphabetsThisBlock[indexIntoBlock] = alphabet;
                // if (logalot) { console.warn(`${lc} alphabetsThisBlock: ${h.pretty(alphabetsThisBlock)} (W: 1bef26a111a4df4a6d501d5a662dd223)`); }
            }
        }
        // if (logalot) { console.warn(`${lc} initial alphabetsThisBlock (${alphabetsThisBlock.length}): ${h.pretty(alphabetsThisBlock)} (W: ce1f77a7065e45cfb12995f097f70af4)`); }

        // if (logalot) { console.warn(`${lc} at this point, each alphabet is the same size (numOfPasses * hash size), but it's not guaranteed that each alphabet will contain the plaintext character.  so go through and extend any alphabets that do not yet contain the plaintext character (I: c75085603497ea684865010dfd8a3b23)`); }

        // at this point, each alphabet is the same size (numOfPasses * hash
        // size), but it's not guaranteed that each alphabet will contain the
        // plaintext character.  so go through and extend any alphabets that do
        // not yet contain the plaintext character
        for (let indexIntoBlock = 0; indexIntoBlock < blockSize; indexIntoBlock++) {
            indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoBlock;
            const hexCharFromData: string = hexEncodedData[indexHexEncodedData];
            let alphabet = alphabetsThisBlock[indexIntoBlock];

            while (!alphabet.includes(hexCharFromData)) {
                // if (logalot) { console.warn(`${lc} alphabet (${alphabet}) has to be extended because it does not contain hexChar (${hexCharFromData}).  (W: a8040eb78f4d123cfa423de33a7f3b23)`); }
                // only executes if alphabet doesnt already contain hexChar
                hash = await execRound_getNextHash({
                    count: recursionsPerHash,
                    prevHash, salt, saltStrategy, hashAlgorithm
                });
                alphabet += hash!;
                prevHash = hash;
            }

            alphabetsThisBlock[indexIntoBlock] = alphabet;
            // if (logalot) { console.warn(`${lc} alphabetsThisBlock (length ${alphabetsThisBlock.length}): ${h.pretty(alphabetsThisBlock)} (W: a86e76aa398d7e4b44dbe0fbb79c1623)`); }
        }
        // if (logalot) { console.warn(`${lc} guaranteed alphabetsThisBlock (${alphabetsThisBlock.length}): ${h.pretty(alphabetsThisBlock)} (W: 8d684c05b116467aa92e946b03160310)`); }

        // if (logalot) { console.warn(`${lc} at this point, each alphabet is at least the minimum size and is guaranteed to have at least once instance of the plaintext hexChar. (W: c6f31445402b1c561670a2dd59530523)`); }
        // at this point, each alphabet is at least the minimum size and is
        // guaranteed to have at least once instance of the plaintext hexChar.
        // if (logalot) { console.warn(`${lc} return prevHash: ${prevHash}`) }
        return { alphabetsThisBlock, prevHash };
    } catch (error) {
        console.error(`${lc} error: ${h.extractErrorMsg(error)}`);
        throw error;
    }
}

async function getEncryptedIndexesThisBlock({
    alphabetsThisBlock,
    blockSize,
    indexHexEncodedDataAtStartOfPass,
    hexEncodedData,
    getIndexOfCharInAlphabet,
}: {
    alphabetsThisBlock: string[],
    blockSize: number,
    indexHexEncodedDataAtStartOfPass: number,
    hexEncodedData: string,
    getIndexOfCharInAlphabet: (alphabet: string, hexChar: string) => number,
}): Promise<number[]> {
    const lc = `[${getEncryptedIndexesThisBlock.name}]`;
    try {
        const resIndexes: number[] = [];
        for (let indexIntoBlock = 0; indexIntoBlock < blockSize; indexIntoBlock++) {
            const indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoBlock;
            const alphabet = alphabetsThisBlock[indexIntoBlock];
            const encryptedIndexIntoAlphabet = getIndexOfCharInAlphabet(alphabet, hexEncodedData[indexHexEncodedData]);
            resIndexes.push(encryptedIndexIntoAlphabet);
        }

        return resIndexes;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}
