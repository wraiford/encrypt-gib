
/**
 * Test helper functions.
 */

// import * as h from './helper.mjs';
import * as h from '@ibgib/helper-gib';
import { firstOfAll, ifWe, ifWeMight, iReckon, respecfully, respecfullyDear } from '@ibgib/helper-gib/dist/respec-gib/respec-gib.mjs';
const maam = `[${import.meta.url}]`, sir = maam;

import * as c from '../constants.mjs';
import { SaltStrategy, HashAlgorithm, } from '../types.mjs';
import { decryptToHex_blockMode } from './decrypt-to-hex-block-mode.mjs';

// const SIMPLEST_DATA = 'a';
// /**
//  * Just looking to do some basic characters, not all unicode (not my specialty).
//  */
// const CHARS_WE_CHAR_ABOUT_SINGLE_STRING = `abcdefghijklmnopqrstuvwxyz\`1234567890-=ABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+,./;'[]\\<>?:"{}|`;
// const CHARS_WE_CHAR_ABOUT: string[] = [];
// for (let i = 0; i < CHARS_WE_CHAR_ABOUT_SINGLE_STRING.length; i++) {
//     const char = CHARS_WE_CHAR_ABOUT_SINGLE_STRING[i];
//     CHARS_WE_CHAR_ABOUT.push(char);
// }

// const COMPLEXEST_DATA_WE_CARE_ABOUT_RIGHT_NOW = `The quick brown fox jumped over the lazy dogs.

// ${CHARS_WE_CHAR_ABOUT_SINGLE_STRING}

// \n\n
// \`


// `;

// /**
//  * requires call to `initData` below
//  */
let LONG_DATA = "this requires a call to initData function below to initialize";
// const TEST_DATAS: string[] = [
//     SIMPLEST_DATA,
//     // CHARS_WE_CHAR_ABOUT_SINGLE_STRING,
//     // ...CHARS_WE_CHAR_ABOUT, // takes awhile, adds lots of test permutations
// ];

// /**
//  * This initial recursion only happens once per encryption/decryption.
//  *
//  * ## notes
//  *
//  * 0 initialRecursions will default to the DEFAULT_INITIAL_RECURSIONS value in constants. This is expected behavior.
//  */
// const TEST_INITIAL_RECURSIONS = [0, 1, 20000];
// /**
//  * any higher and it goes pretty slow for testing purposes on my machine
//  *
//  * REMEMBER: This happens **per hex character encrypted/decrypted**.
//  */
// const TEST_RECURSIONS_PER_HASH = [1, 15];
// const TEST_SALTS = [
//     ...CHARS_WE_CHAR_ABOUT.slice(0, 2),
//     CHARS_WE_CHAR_ABOUT_SINGLE_STRING,
// ];
// const TEST_SALT_STRATEGIES: SaltStrategy[] = Object.keys(SaltStrategy).map((x: string) => SaltStrategy[x] as SaltStrategy);
// const SHORT_SECRET = 'p4ss';
// /**
//  * requires call to `initData` below
//  */
// let LONG_SECRET = "this requires a call to initData function below to initialize";
// const TEST_SECRETS: string[] = [
//     // 'secret p4$$w0rd 3v3n',
//     // ...CHARS_WE_CHAR_ABOUT.slice(0, 2),
//     // CHARS_WE_CHAR_ABOUT_SINGLE_STRING, // imitates a long password with special characters
// ];
// const TEST_DELIMITERS = [
//     c.DEFAULT_ENCRYPTED_DATA_DELIMITER,
//     // ' ',
//     // feel free to add more but increases testing time
// ];
// const TEST_CONFIRM_VALUES: boolean[] = [true, false];

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

await respecfully(sir, `decryptToHex_blockMode`, async () => {
    await respecfully(sir, `simplest cases`, async () => {
        const salt = "q";
        const hexEncodedData = 'abc123def';
        // const salt = 'salty1';
        const saltStrategy = SaltStrategy.appendPerHash;
        const initialRecursions = 10;
        const recursionsPerHash = 1;
        const secret = 'aaa';
        const hashAlgorithm: HashAlgorithm = 'SHA-256';
        const encryptedDataDelimiter = c.DEFAULT_ENCRYPTED_DATA_DELIMITER;
        const maxBlockSize = 3;
        const numOfPasses = 1;

        await respecfully(sir, `testing both indexingModes`, async () => {
            {
                const expectedHexEncodedData = 'abc123def';
                await ifWe(sir, `indexOf, expected hex: "${expectedHexEncodedData}"`, async () => {
                    const decryptedData = await decryptToHex_blockMode({
                        encryptedData: '21,23,76,0,8,5,7,6,11',
                        initialRecursions,
                        recursionsPerHash,
                        salt,
                        saltStrategy,
                        secret,
                        hashAlgorithm: HashAlgorithm.sha_256,
                        encryptedDataDelimiter: c.DEFAULT_ENCRYPTED_DATA_DELIMITER,
                        maxBlockSize,
                        numOfPasses,
                    });
                    // console.log(decryptedData)
                    iReckon(sir, decryptedData).asTo('encryptedData').isGonnaBe(expectedHexEncodedData);
                });
            }
            {
                const expectedHexEncodedData = 'abc123def';
                await ifWe(sir, `lastIndexOf, expected hex: "${expectedHexEncodedData}"`, async () => {
                    const decryptedData = await decryptToHex_blockMode({
                        encryptedData: '62,36,115,63,62,54,61,59,48',
                        initialRecursions,
                        recursionsPerHash,
                        salt,
                        saltStrategy,
                        secret,
                        hashAlgorithm: HashAlgorithm.sha_256,
                        encryptedDataDelimiter: c.DEFAULT_ENCRYPTED_DATA_DELIMITER,
                        maxBlockSize,
                        numOfPasses,
                    });
                    // console.log(decryptedData)
                    iReckon(sir, decryptedData).asTo('encryptedData').isGonnaBe(expectedHexEncodedData);
                });
            }
        });
    });
});
