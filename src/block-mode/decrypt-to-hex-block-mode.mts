import * as h from '@ibgib/helper-gib';

import { doInitialRecursions_keystretch, execRound_getNextHash, getPreHash } from "../common/encrypt-decrypt-common.mjs";
import { AlphabetIndexingMode, HashAlgorithm, SaltStrategy } from "../types.mjs";

/**
 * Internal function that takes a given encryptedData, in the form of a
 * delimited string of indexes, and decrypts it back into encoded hex (not the
 * original unencrypted data!).
 *
 * It does this by reconstructing the JIT alphabets for each section, just as
 * was done in the encrypting process. It then uses the encrypted indexes into
 * these alphabets and rebuilds the multipass section's plaintext **hex**.
 *
 * For documentation on args, see `DecryptArgs`.
 *
 * @returns unencrypted, but still hex-encoded plaintext string
 */
export async function decryptToHex_blockMode({
    encryptedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
    maxBlockSize,
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
    maxBlockSize: number,
    numOfPasses: number,
}): Promise<string> {
    const lc = `[${decryptToHex_blockMode.name}]`;

    try {
        // set up "prevHash" as a starting point, similar to key-stretching
        let prevHash = await doInitialRecursions_keystretch({
            secret,
            initialRecursions,
            salt,
            saltStrategy: saltStrategy!,
            hashAlgorithm: hashAlgorithm!,
        });

        // we have our prevHash starting point, so now we can iterate through the data
        let encryptedDataIndexes: number[] =
            encryptedData.split(encryptedDataDelimiter).map((nString: string) => parseInt(nString));
        let decryptedDataArray: string[] = [];

        // re-play multipass building of alphabets. Section by section, first
        // create the minimum number of alphabets. Then iterate through each
        // cipher index, extending individual alphabets JIT/on demand depending
        // on the cipher index, i.e., if the index is larger than the existing
        // alphabet, then we extend it another round.

        // set the initial pass length.
        let totalLength = encryptedDataIndexes.length;
        let blockSize = maxBlockSize;
        if (blockSize > totalLength) { blockSize = totalLength; }

        /**
         * We are doing multiple passes, but possibly only on subsets of
         * encryptedDataIndexes. This variable is the number of sections that we're
         * doing. The final section may be less than a full pass section.
         *
         * _note: I am avoiding the use of "block" since that is an overloaded term in cryptography and is usually related to padding._
         */
        let blockSections = Math.ceil(totalLength / blockSize);
        /**
         * the final pass may be less than the pass length.
         */
        let finalBlockSize = (totalLength % blockSize) || blockSize; // if 0, then the last pass is full length
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
        for (let indexOfBlock = 0; indexOfBlock < blockSections; indexOfBlock++) {

            // adjust the blockSize if it's the final one which might be shorter
            const isFinalBlock = indexOfBlock === blockSections - 1;
            if (isFinalBlock) { blockSize = finalBlockSize; }

            const resGetAlphabets = await getAlphabetsThisBlock({
                blockSize,
                indexEncryptedDataIndexesAtStartOfPass,
                numOfPasses,
                encryptedDataIndexes,
                recursionsPerHash,
                salt,
                saltStrategy,
                prevHash,
                hashAlgorithm,
            });

            let alphabetsThisBlock = resGetAlphabets.alphabetsThisBlock;
            prevHash = resGetAlphabets.prevHash; // used in next section if there is one

            const decryptedDataArrayThisBlock = await getDecryptedDataArrayThisBlock({
                alphabetsThisBlock,
                blockSize,
                indexEncryptedDataIndexesAtStartOfPass,
                encryptedDataIndexes,
            });

            decryptedDataArray = decryptedDataArray.concat(decryptedDataArrayThisBlock);

            indexEncryptedDataIndexesAtStartOfPass += blockSize;
        }

        // reconstitute the decryptedHex
        const decryptedHex: string = decryptedDataArray.join('');
        return decryptedHex;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}

/**
 * internal function that builds the JIT alphabets for a given multipass
 * section.
 *
 * @returns alphabetsThisBlock array of alphabets and the final `prevHash` for use in the next multipass section (if any).
 */
async function getAlphabetsThisBlock({
    blockSize,
    numOfPasses,
    indexEncryptedDataIndexesAtStartOfPass,
    encryptedDataIndexes,
    recursionsPerHash,
    salt,
    saltStrategy,
    prevHash,
    hashAlgorithm,
}: {
    /**
     * Size of the multipass section, i.e. number of characters to
     * encrypt/decrypt as a whole.
     */
    blockSize: number,
    /**
     * Number of times to iterate over the multipass section
     */
    numOfPasses: number,
    indexEncryptedDataIndexesAtStartOfPass: number,
    encryptedDataIndexes: number[],
    recursionsPerHash: number,
    salt: string,
    saltStrategy: SaltStrategy,
    prevHash: string,
    hashAlgorithm: HashAlgorithm,
}): Promise<{ alphabetsThisBlock: string[], prevHash: string }> {
    const lc = `[${getAlphabetsThisBlock.name}]`;
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
        let alphabetsThisBlock: string[] = [];
        /** index into the `encryptedDataIndexes` that we're working with */
        let indexEncryptedDataIndexes: number;
        let hash: string;
        // first construct all alphabets for this pass section using the
        // given number of passes. Note that zero or more of these alphabets
        // may NOT include the hex character to encode, but this will be
        // addressed in the next step.
        for (let passNum = 0; passNum < numOfPasses; passNum++) {
            for (let indexIntoBlock = 0; indexIntoBlock < blockSize; indexIntoBlock++) {
                indexEncryptedDataIndexes = indexEncryptedDataIndexesAtStartOfPass + indexIntoBlock;
                let alphabet = alphabetsThisBlock[indexIntoBlock] ?? '';

                hash = await execRound_getNextHash({
                    count: recursionsPerHash,
                    prevHash, salt, saltStrategy, hashAlgorithm
                });
                alphabet += hash;
                prevHash = hash;

                alphabetsThisBlock[indexIntoBlock] = alphabet;
            }
        }

        // at this point, each alphabet is the same size (numOfPasses * hash
        // size), but it's not guaranteed that each alphabet will contain the
        // plaintext character.  so go through and extend any alphabets that do
        // not yet contain the plaintext character
        for (let indexIntoBlock = 0; indexIntoBlock < blockSize; indexIntoBlock++) {
            indexEncryptedDataIndexes = indexEncryptedDataIndexesAtStartOfPass + indexIntoBlock;
            const encryptedIndex: number = encryptedDataIndexes[indexEncryptedDataIndexes];
            let alphabet = alphabetsThisBlock[indexIntoBlock];

            // while (!alphabet.includes(hexCharFromData)) {
            while (alphabet.at(encryptedIndex) === undefined) {
                // only executes if alphabet isn't long enough for index
                hash = await execRound_getNextHash({
                    count: recursionsPerHash,
                    prevHash, salt, saltStrategy, hashAlgorithm
                });
                alphabet += hash;
                prevHash = hash;
            }

            alphabetsThisBlock[indexIntoBlock] = alphabet;
        }

        // at this point, each alphabet is at least the minimum size and is
        // guaranteed to have at least once instance of the plaintext hexChar.
        return { alphabetsThisBlock, prevHash };
    } catch (error) {
        console.error(`${lc} error: ${h.extractErrorMsg(error)}`);
        throw error;
    }
}

/**
 * Takes the incoming encrypted indexes for a multipass section and maps them to
 * plaintext.
 *
 * @param args see individual param docs
 * @returns plaintext as an array of strings
 */
async function getDecryptedDataArrayThisBlock({
    alphabetsThisBlock,
    blockSize,
    indexEncryptedDataIndexesAtStartOfPass,
    encryptedDataIndexes,
}: {
    /**
     * All alphabets for this multipass section that we have already created in
     * a previous step.
     */
    alphabetsThisBlock: string[],
    /**
     * Size of the multipass section that we are processing as a whole.
     */
    blockSize: number,
    /**
     * Start of the multipass section, used to index into {@link encryptedDataIndexes}.
     */
    indexEncryptedDataIndexesAtStartOfPass: number,
    /**
     * Reference to the entire encrypted data array.
     *
     * We will index into this array and get the "encrypted data index" which is
     * the index into the alphabet for that encrypted character.
     */
    encryptedDataIndexes: number[],
}): Promise<string[]> {
    const lc = `[${getDecryptedDataArrayThisBlock.name}]`;
    try {
        const resDataArray: string[] = [];

        for (let indexIntoBlock = 0; indexIntoBlock < blockSize; indexIntoBlock++) {
            let indexEncryptedDataIndexes = indexEncryptedDataIndexesAtStartOfPass + indexIntoBlock;
            const encryptedIndex: number = encryptedDataIndexes[indexEncryptedDataIndexes];
            let alphabet = alphabetsThisBlock[indexIntoBlock];
            let decryptedCharString = alphabet[encryptedIndex];
            resDataArray.push(decryptedCharString);
        }

        return resDataArray;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}
