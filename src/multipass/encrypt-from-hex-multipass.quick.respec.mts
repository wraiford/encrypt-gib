
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
    BruteForceShortCircuitMitigationInfo, AlphabetIndexingMode,
    ALPHABET_INDEXING_MODES,
    SALT_STRATEGIES
} from '../types.mjs';
import { encodeStringToHexString } from '../helper.mjs';
import { encryptFromHex_multipass } from './encrypt-from-hex-multipass.mjs';

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
// const SHORT_SECRET = 'p4ss';
// /**
//  * requires call to `initData` below
//  */
// let LONG_SECRET = "this requires a call to initData function below to initialize";
const TEST_SECRETS: string[] = [
    'aaa',
    'secret p4$$w0rd 3v3n',
    // ...CHARS_WE_CHAR_ABOUT.slice(0, 2),
    // CHARS_WE_CHAR_ABOUT_SINGLE_STRING, // imitates a long password with special characters
];
const TEST_DELIMITERS = [
    c.DEFAULT_ENCRYPTED_DATA_DELIMITER,
    ' ',
    // feel free to add more but increases testing time
];
// const TEST_CONFIRM_VALUES: boolean[] = [true, false];
// // throw new Error('test BruteForceShortCircuitMitigationInfo settings not implemented yet');
// // const BRUTE_MITIGATION_SETTINGS: (BruteForceShortCircuitMitigationInfo | undefined)[] = [
// //     undefined,
// //     {
// //         additionalPasses: 1,
// //     }
// // ];

async function initData(): Promise<void> {
    for (let i = 0; i < 10; i++) {
        let uuid = await h.getUUID();
        LONG_DATA += uuid + '\n';
    }
    // for (let i = 0; i < 100; i++) {
    //     let uuid = await h.getUUID();
    //     LONG_SECRET += uuid + '\n';
    // }
    // TEST_DATAS.push(LONG_DATA); // comment this if you don't want a long data test
    // TEST_SECRETS.push(LONG_SECRET); // comment this if you don't want a long secret test
}
await initData(); // yay top-level await

const MAX_PASS_SECTION_LENGTHS: number[] = [
    1,
    10,
    42,
    c.DEFAULT_MAX_PASS_SECTION_LENGTH, // 500 atow
];
const NUM_OF_PASSES: number[] = [
    1,
    2,
    c.DEFAULT_NUM_OF_PASSES, // 4 atow
];

await respecfully(sir, `encryptFromHex_multipass`, async () => {
    await respecfully(sir, `simplest cases`, async () => {


        // for (const indexingMode of ALPHABET_INDEXING_MODES) {}
        // const indexingMode: AlphabetIndexingMode = AlphabetIndexingMode.indexOf;
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
            const maxPassSectionLength = 3;
            const numOfPasses = 1;
            await ifWe(sir, `[${AlphabetIndexingMode.indexOf}][${hexEncodedData}]`, async () => {
                const encryptedData = await encryptFromHex_multipass({
                    hexEncodedData,
                    initialRecursions,
                    recursionsPerHash,
                    salt,
                    saltStrategy,
                    secret,
                    hashAlgorithm,
                    encryptedDataDelimiter,
                    indexingMode: AlphabetIndexingMode.indexOf,
                    maxPassSectionLength,
                    numOfPasses,
                });
                iReckon(sir, encryptedData).asTo('encryptedData').isGonnaBeTruthy();
                iReckon(sir, encryptedData.length > hexEncodedData.length).asTo('encryptedData.length >= hexEncodedData.length').isGonnaBeTrue();
                iReckon(sir, encryptedData.split(encryptedDataDelimiter).length).isGonnaBe(hexEncodedData.length);
            });
            await ifWe(sir, `[${AlphabetIndexingMode.lastIndexOf}][${hexEncodedData}]`, async () => {
                const encryptedData = await encryptFromHex_multipass({
                    hexEncodedData,
                    initialRecursions,
                    recursionsPerHash,
                    salt,
                    saltStrategy,
                    secret,
                    hashAlgorithm,
                    encryptedDataDelimiter,
                    indexingMode: AlphabetIndexingMode.lastIndexOf,
                    maxPassSectionLength,
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
            const maxPassSectionLength = 3;
            const numOfPasses = 1;

            await ifWe(sir, `[${AlphabetIndexingMode.indexOf}][${hexEncodedData}]`, async () => {
                const encryptedData = await encryptFromHex_multipass({
                    hexEncodedData,
                    initialRecursions,
                    recursionsPerHash,
                    salt,
                    saltStrategy,
                    secret,
                    hashAlgorithm,
                    encryptedDataDelimiter,
                    indexingMode: AlphabetIndexingMode.indexOf,
                    maxPassSectionLength,
                    numOfPasses,
                });
                iReckon(sir, encryptedData).asTo('encryptedData').isGonnaBeTruthy();
                iReckon(sir, encryptedData.length > hexEncodedData.length).asTo('encryptedData.length >= hexEncodedData.length').isGonnaBeTrue();
                iReckon(sir, encryptedData.split(encryptedDataDelimiter).length).isGonnaBe(hexEncodedData.length);
            });

            await ifWe(sir, `[${AlphabetIndexingMode.lastIndexOf}][${hexEncodedData}]`, async () => {
                const encryptedData = await encryptFromHex_multipass({
                    hexEncodedData,
                    initialRecursions,
                    recursionsPerHash,
                    salt,
                    saltStrategy,
                    secret,
                    hashAlgorithm,
                    encryptedDataDelimiter,
                    indexingMode: AlphabetIndexingMode.lastIndexOf,
                    maxPassSectionLength,
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
                        const encryptedData = await encryptFromHex_multipass({
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

    await respecfully(sir, `different parameter sets`, async () => {

        const encryptedDataDelimiter = c.DEFAULT_ENCRYPTED_DATA_DELIMITER;
        const secret = 'great pw here (jk)';
        const hashAlgorithm = HashAlgorithm.sha_256;
        const salt = 'salt here yo';
        const initialRecursions = 5;
        const recursionsPerHash = 3;

        for (const dataToEncrypt of TEST_DATAS) {
            for (const saltStrategy of TEST_SALT_STRATEGIES) {
                for (const maxPassSectionLength of MAX_PASS_SECTION_LENGTHS) {
                    for (const numOfPasses of NUM_OF_PASSES) {
                        for (const indexingMode of ALPHABET_INDEXING_MODES) {

                            const hexEncodedData = await encodeStringToHexString(dataToEncrypt);

                            await respecfully(sir, `datalen:${hexEncodedData.length}|initRec:${initialRecursions}|recPer:${recursionsPerHash}|saltStrat:${saltStrategy}|maxPassLen:${maxPassSectionLength}|numPass:${numOfPasses}|mode:${indexingMode}`, async () => {
                                // i have manually eyeballed guaranteed alphabet extensions with
                                // this parameter set + data and there were no alphabets with sizes
                                // larger than a single hash, as there are no extra extensions and
                                // the numOfPasses = 1
                                // const hexEncodedData = 'abc123def123412341234abcabcabcdef0123456789a'; // length 44
                                // const numOfPasses = 50;
                                await ifWe(sir, `[${hexEncodedData}]`, async () => {
                                    const encryptedData = await encryptFromHex_multipass({
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