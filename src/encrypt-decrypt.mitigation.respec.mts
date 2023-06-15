/**
 * Test helper functions.
 */

import * as h from '@ibgib/helper-gib';
import { firstOfAll, ifWe, ifWeMight, iReckon, respecfully } from '@ibgib/helper-gib/dist/respec-gib/respec-gib.mjs';
const maam = `[${import.meta.url}]`, sir = maam;

import * as c from './constants.mjs';
import * as encryptGib from './encrypt-decrypt.mjs';
import {
    SaltStrategy, HashAlgorithm, ALPHABET_INDEXING_MODES, SALT_STRATEGIES,
    BlockModeOptions,
} from './types.mjs';

const SIMPLEST_DATA = 'a';
/**
 * Just looking to do some basic characters, not all unicode (not my specialty).
 */
const CHARS_WE_CHAR_ABOUT_SINGLE_STRING = `abcdefghijklmnopqrstuvwxyz\`1234567890-=ABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+,./;'[]\\<>?:"{}|`;
const CHARS_WE_CHAR_ABOUT: string[] = [];
for (let i = 0; i < CHARS_WE_CHAR_ABOUT_SINGLE_STRING.length; i++) {
    const char = CHARS_WE_CHAR_ABOUT_SINGLE_STRING[i];
    CHARS_WE_CHAR_ABOUT.push(char);
}

const COMPLEXEST_DATA_WE_CARE_ABOUT_RIGHT_NOW = `The quick brown fox jumped over the lazy dogs.

${CHARS_WE_CHAR_ABOUT_SINGLE_STRING}

\n\n
\`


`;

/**
 * requires call to `initData` below
 */
let LONG_DATA = "this requires a call to initData function below to initialize";
const TEST_DATAS: string[] = [
    SIMPLEST_DATA,
    // CHARS_WE_CHAR_ABOUT_SINGLE_STRING,
    // ...CHARS_WE_CHAR_ABOUT, // takes awhile, adds lots of test permutations
];

/**
 * This initial recursion only happens once per encryption/decryption.
 *
 * ## notes
 *
 * 0 initialRecursions will default to the DEFAULT_INITIAL_RECURSIONS value in constants. This is expected behavior.
 */
const TEST_INITIAL_RECURSIONS = [0, 1, 20000];
/**
 * any higher and it goes pretty slow for testing purposes on my machine
 *
 * REMEMBER: This happens **per hex character encrypted/decrypted**.
 */
const TEST_RECURSIONS_PER_HASH = [1, 15];
const TEST_SALTS = [
    ...CHARS_WE_CHAR_ABOUT.slice(0, 2),
    CHARS_WE_CHAR_ABOUT_SINGLE_STRING,
];
const TEST_SALT_STRATEGIES: SaltStrategy[] = SALT_STRATEGIES.concat();
const SHORT_SECRET = 'p4ss';
/**
 * requires call to `initData` below
 */
let LONG_SECRET = "this requires a call to initData function below to initialize";
const TEST_SECRETS: string[] = [
    // 'secret p4$$w0rd 3v3n',
    // ...CHARS_WE_CHAR_ABOUT.slice(0, 2),
    // CHARS_WE_CHAR_ABOUT_SINGLE_STRING, // imitates a long password with special characters
];
const TEST_DELIMITERS = [
    c.DEFAULT_ENCRYPTED_DATA_DELIMITER,
    // ' ',
    // feel free to add more but increases testing time
];
const TEST_CONFIRM_VALUES: boolean[] = [true, false];

async function initData(): Promise<void> {
    for (let i = 0; i < 500; i++) {
        let uuid = await h.getUUID();
        LONG_DATA += uuid + '\n';
    }
    for (let i = 0; i < 100; i++) {
        let uuid = await h.getUUID();
        LONG_SECRET += uuid + '\n';
    }
    TEST_DATAS.push(LONG_DATA); // comment this if you don't want a long data test
    TEST_SECRETS.push(LONG_SECRET); // comment this if you don't want a long secret test
}
await initData(); // yay top-level await

await respecfully(sir, `initial brute force mitigation tests`, async () => {
    await respecfully(sir, `indexingMode`, async () => {
        const secretA = 'aaa';
        const dataToEncrypt = LONG_DATA;
        const initialRecursions = 10;
        const recursionsPerHash = 1;
        const salt = 'salt1';
        const saltStrategy = SaltStrategy.appendPerHash;
        const hashAlgorithm = HashAlgorithm.sha_256;
        const encryptedDataDelimiter = c.DEFAULT_ENCRYPTED_DATA_DELIMITER;
        const blockMode: BlockModeOptions = {
            maxBlockSize: 50,
            numOfPasses: 4,
        }

        for (const indexingMode of ALPHABET_INDEXING_MODES) {
            await respecfully(sir, `${indexingMode}`, async () => {
                await ifWe(sir, `enc-dec`, async () => {

                    const resEncrypt = await encryptGib.encrypt({
                        dataToEncrypt,
                        initialRecursions,
                        recursionsPerHash,
                        salt,
                        saltStrategy,
                        secret: secretA,
                        hashAlgorithm,
                        encryptedDataDelimiter,
                        indexingMode,
                        blockMode,
                    });
                    iReckon(sir, (resEncrypt.errors || []).length).asTo('resEncrypt.errors || []').isGonnaBe(0);

                    // console.log(`encrypted pass 1: ${h.pretty(resEncrypt)}`);

                    const resDecrypt = await encryptGib.decrypt({
                        encryptedData: resEncrypt.encryptedData!,
                        initialRecursions,
                        recursionsPerHash,
                        salt,
                        saltStrategy,
                        secret: secretA,
                        hashAlgorithm,
                        encryptedDataDelimiter,
                        indexingMode,
                        blockMode,
                    });

                    iReckon(sir, dataToEncrypt).asTo('dataToEncrypt===decryptedData').isGonnaBe(resDecrypt.decryptedData);
                });
            });
        }
        // await ifWe(sir, 'testing mismatching passwords', async () => {

        //     const secretA = 'aaa';

        //     const dataToEncrypt = 'abcdefghi';
        //     const initialRecursions = 10;
        //     const recursionsPerHash = 1;
        //     const salt = 'salt1';
        //     const saltStrategy = SaltStrategy.initialAppend;
        //     const hashAlgorithm = HashAlgorithm.sha_256;
        //     const encryptedDataDelimiter = c.DEFAULT_ENCRYPTED_DATA_DELIMITER;


        //     console.log(`dataToEncrypt: ${dataToEncrypt}`);
        //     let hexA = await encodeStringToHexString(dataToEncrypt);
        //     console.log(`dataToEncrypt (hex): ${hexA}`);

        //     const resEncrypt_secretA = await encryptGib.encrypt({
        //         dataToEncrypt,
        //         initialRecursions,
        //         recursionsPerHash,
        //         salt,
        //         saltStrategy,
        //         secret: secretA,
        //         hashAlgorithm,
        //         encryptedDataDelimiter,
        //         confirm: true,
        //     });
        //     iReckon(sir, (resEncrypt_secretA.errors || []).length).asTo('resEncrypt_secretA.errors || []').isGonnaBe(0);

        //     console.log(`encrypted pass 1: ${h.pretty(resEncrypt_secretA)}`);

        //     const resDecrypt_secretShortCircuit = await encryptGib.decrypt({
        //         encryptedData: '33,28,14,20',
        //         // encryptedData: resEncrypt_secretA.encryptedData!,
        //         initialRecursions,
        //         recursionsPerHash,
        //         salt,
        //         saltStrategy,
        //         secret: secretA,
        //         hashAlgorithm,
        //         encryptedDataDelimiter,
        //     })
        //     console.log(`resDecrypt_secretShortCircuit: ${h.pretty(resDecrypt_secretShortCircuit)}`);
        //     let hexSC = await encodeStringToHexString(resDecrypt_secretShortCircuit.decryptedData!)
        //     console.log(`hex of resDecrypt_secretShortCircuit.decryptedData!: ${hexSC}`);


        // });
    });
});
