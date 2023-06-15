
/**
 * Test helper functions.
 */

// import * as h from './helper.mjs';
import * as h from '@ibgib/helper-gib';
import { firstOfAll, ifWe, ifWeMight, iReckon, respecfully, respecfullyDear } from '@ibgib/helper-gib/dist/respec-gib/respec-gib.mjs';
const maam = `[${import.meta.url}]`, sir = maam;

import * as c from '../constants.mjs';
import * as encryptGib from '../encrypt-decrypt.mjs';
import {
    SaltStrategy, HashAlgorithm,
    AlphabetIndexingMode,
    ALPHABET_INDEXING_MODES,
    SALT_STRATEGIES
} from '../types.mjs';
import { encodeStringToHexString } from '../helper.mjs';
import { encryptFromHex_blockMode } from './encrypt-from-hex-block-mode.mjs';

const SIMPLEST_DATA = 'a';
// /**
//  * Just looking to do some basic characters, not all unicode (not my specialty).
//  */
const CHARS_WE_CHAR_ABOUT_SINGLE_STRING = `abcdefghijklmnopqrstuvwxyz\`1234567890-=ABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+,./;'[]\\<>?:"{}|`;
const CHARS_WE_CHAR_ABOUT: string[] = [];
for (let i = 0; i < CHARS_WE_CHAR_ABOUT_SINGLE_STRING.length; i++) {
    const char = CHARS_WE_CHAR_ABOUT_SINGLE_STRING[i];
    CHARS_WE_CHAR_ABOUT.push(char);
}

// const COMPLEXEST_DATA_WE_CARE_ABOUT_RIGHT_NOW = `The quick brown fox jumped over the lazy dogs.

// ${CHARS_WE_CHAR_ABOUT_SINGLE_STRING}

// \n\n
// \`


// `;

// /**
//  * requires call to `initData` below
//  */
let LONG_DATA = "this requires a call to initData function below to initialize";
const TEST_DATAS: string[] = [
    SIMPLEST_DATA,
    CHARS_WE_CHAR_ABOUT_SINGLE_STRING,
    // ...CHARS_WE_CHAR_ABOUT, // takes awhile, adds lots of test permutations
];

// /**
//  * This initial recursion only happens once per encryption/decryption.
//  *
//  * ## notes
//  *
//  * 0 initialRecursions will default to the DEFAULT_INITIAL_RECURSIONS value in constants. This is expected behavior.
//  */
const TEST_INITIAL_RECURSIONS = [1, 100];
// /**
//  * any higher and it goes pretty slow for testing purposes on my machine
//  *
//  * REMEMBER: This happens **per hex character encrypted/decrypted**.
//  */
const TEST_RECURSIONS_PER_HASH = [1, 5];
const TEST_SALTS = [
    ...CHARS_WE_CHAR_ABOUT.slice(0, 2),
    CHARS_WE_CHAR_ABOUT_SINGLE_STRING,
];
const TEST_SALT_STRATEGIES: SaltStrategy[] = [
    SaltStrategy.appendPerHash,
    SaltStrategy.initialPrepend,
];

async function initData(): Promise<void> {
    for (let i = 0; i < 10; i++) {
        let uuid = await h.getUUID();
        LONG_DATA += uuid + '\n';
    }
}
await initData(); // yay top-level await

const MAX_BLOCK_SIZES: number[] = [
    1,
    10,
    42,
    c.DEFAULT_MAX_BLOCK_SIZE, // 500 atow
];
const NUM_OF_PASSES: number[] = [
    1,
    2,
    c.DEFAULT_NUM_OF_PASSES, // 4 atow
];

await respecfully(sir, `encryptFromHex_blockMode`, async () => {
    await respecfully(sir, `simplest cases`, async () => {
        await respecfully(sir, `varying index modes, no manual jit alphabet extensions required to guarantee`, async () => {
            // i have manually eyeballed guaranteed alphabet extensions with
            // this parameter set + data and there were no alphabets with sizes
            // larger than a single hash, as there are no extra extensions and
            // the numOfPasses = 1
            const hexEncodedData = 'abc123def';
            const salt = 'salty';
            const saltStrategy = SaltStrategy.appendPerHash;
            const initialRecursions = 10;
            const recursionsPerHash = 1;
            const secret = 'aaa';
            const hashAlgorithm: HashAlgorithm = 'SHA-256';
            const encryptedDataDelimiter = c.DEFAULT_ENCRYPTED_DATA_DELIMITER;
            const maxBlockSize = 3;
            const numOfPasses = 1;
            await ifWe(sir, `[${AlphabetIndexingMode.indexOf}][${hexEncodedData}]`, async () => {
                const encryptedData = await encryptFromHex_blockMode({
                    hexEncodedData,
                    initialRecursions,
                    recursionsPerHash,
                    salt,
                    saltStrategy,
                    secret,
                    hashAlgorithm,
                    encryptedDataDelimiter,
                    indexingMode: AlphabetIndexingMode.indexOf,
                    maxBlockSize,
                    numOfPasses,
                });
                iReckon(sir, encryptedData).asTo('encryptedData').isGonnaBeTruthy();
                iReckon(sir, encryptedData.length > hexEncodedData.length).asTo('encryptedData.length >= hexEncodedData.length').isGonnaBeTrue();
                iReckon(sir, encryptedData.split(encryptedDataDelimiter).length).isGonnaBe(hexEncodedData.length);
            });
            await ifWe(sir, `[${AlphabetIndexingMode.lastIndexOf}][${hexEncodedData}]`, async () => {
                const encryptedData = await encryptFromHex_blockMode({
                    hexEncodedData,
                    initialRecursions,
                    recursionsPerHash,
                    salt,
                    saltStrategy,
                    secret,
                    hashAlgorithm,
                    encryptedDataDelimiter,
                    indexingMode: AlphabetIndexingMode.lastIndexOf,
                    maxBlockSize,
                    numOfPasses,
                });
                iReckon(sir, encryptedData).asTo('encryptedData').isGonnaBeTruthy();
                iReckon(sir, encryptedData.length > hexEncodedData.length).asTo('encryptedData.length >= hexEncodedData.length').isGonnaBeTrue();
                iReckon(sir, encryptedData.split(encryptedDataDelimiter).length).isGonnaBe(hexEncodedData.length);
            });
        });

        await respecfully(sir, `varying index modes, but there is at least 1 jit alphabet extensions required to guarantee`, async () => {
            // i have manually eyeballed guaranteed alphabet extensions with
            // this parameter set + data and there was at least one alphabet
            // with sizes larger than a single hash, even though the we have set
            // the numOfPasses = 1
            const salt = "q";
            const hexEncodedData = 'abc123def';
            const saltStrategy = SaltStrategy.appendPerHash;
            const initialRecursions = 10;
            const recursionsPerHash = 1;
            const secret = 'aaa';
            const hashAlgorithm: HashAlgorithm = 'SHA-256';
            const encryptedDataDelimiter = c.DEFAULT_ENCRYPTED_DATA_DELIMITER;
            const maxBlockSize = 3;
            const numOfPasses = 1;

            await ifWe(sir, `[${AlphabetIndexingMode.indexOf}][${hexEncodedData}]`, async () => {
                const encryptedData = await encryptFromHex_blockMode({
                    hexEncodedData,
                    initialRecursions,
                    recursionsPerHash,
                    salt,
                    saltStrategy,
                    secret,
                    hashAlgorithm,
                    encryptedDataDelimiter,
                    indexingMode: AlphabetIndexingMode.indexOf,
                    maxBlockSize,
                    numOfPasses,
                });
                iReckon(sir, encryptedData).asTo('encryptedData').isGonnaBeTruthy();
                iReckon(sir, encryptedData.length > hexEncodedData.length).asTo('encryptedData.length >= hexEncodedData.length').isGonnaBeTrue();
                iReckon(sir, encryptedData.split(encryptedDataDelimiter).length).isGonnaBe(hexEncodedData.length);
            });

            await ifWe(sir, `[${AlphabetIndexingMode.lastIndexOf}][${hexEncodedData}]`, async () => {
                const encryptedData = await encryptFromHex_blockMode({
                    hexEncodedData,
                    initialRecursions,
                    recursionsPerHash,
                    salt,
                    saltStrategy,
                    secret,
                    hashAlgorithm,
                    encryptedDataDelimiter,
                    indexingMode: AlphabetIndexingMode.lastIndexOf,
                    maxBlockSize,
                    numOfPasses,
                });
                iReckon(sir, encryptedData).asTo('encryptedData').isGonnaBeTruthy();
                iReckon(sir, encryptedData.length > hexEncodedData.length).asTo('encryptedData.length >= hexEncodedData.length').isGonnaBeTrue();
                iReckon(sir, encryptedData.split(encryptedDataDelimiter).length).isGonnaBe(hexEncodedData.length);
            });

            for (let i = 0; i < ALPHABET_INDEXING_MODES.length; i++) {
                const indexingMode = ALPHABET_INDEXING_MODES[i];
                await ifWe(sir, `${hexEncodedData} should be deterministic`, async () => {
                    const encryptedDataResults: string[] = [];
                    // repeat in the loop and the output should always be the same
                    for (let i = 0; i < 20; i++) {
                        const encryptedData = await encryptFromHex_blockMode({
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
                        });
                        encryptedDataResults.push(encryptedData);
                    }
                    const firstResult = encryptedDataResults[0];
                    const allAreTheSame = encryptedDataResults.every(x => x === firstResult);
                    iReckon(sir, allAreTheSame).isGonnaBeTrue();
                });
            }
        });
    });

    await respecfully(sir, `different light parameter sets`, async () => {
        const encryptedDataDelimiter = c.DEFAULT_ENCRYPTED_DATA_DELIMITER;
        const secret = 'great pw here (jk)';
        const hashAlgorithm = HashAlgorithm.sha_256;
        const salt = 'salt here yo';
        const initialRecursions = 5;
        const recursionsPerHash = 3;

        for (const dataToEncrypt of TEST_DATAS) {
            for (const saltStrategy of TEST_SALT_STRATEGIES) {
                for (const maxBlockSize of MAX_BLOCK_SIZES) {
                    for (const numOfPasses of NUM_OF_PASSES) {
                        for (const indexingMode of ALPHABET_INDEXING_MODES) {

                            const hexEncodedData = await encodeStringToHexString(dataToEncrypt);

                            await respecfully(sir, `datalen:${hexEncodedData.length}|initRec:${initialRecursions}|recPer:${recursionsPerHash}|saltStrat:${saltStrategy}|maxPassLen:${maxBlockSize}|numPass:${numOfPasses}|mode:${indexingMode}`, async () => {
                                // i have manually eyeballed guaranteed alphabet extensions with
                                // this parameter set + data and there were no alphabets with sizes
                                // larger than a single hash, as there are no extra extensions and
                                // the numOfPasses = 1
                                // const hexEncodedData = 'abc123def123412341234abcabcabcdef0123456789a'; // length 44
                                // const numOfPasses = 50;
                                await ifWe(sir, `[${hexEncodedData}]`, async () => {
                                    const encryptedData = await encryptFromHex_blockMode({
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
                                    });
                                    iReckon(sir, encryptedData).asTo('encryptedData').isGonnaBeTruthy();
                                    iReckon(sir, encryptedData.length > hexEncodedData.length).asTo('encryptedData.length >= hexEncodedData.length').isGonnaBeTrue();
                                    iReckon(sir, encryptedData.split(encryptedDataDelimiter).length).isGonnaBe(hexEncodedData.length);
                                });
                            });
                        }
                    }
                }
            }
        }
    });

});
