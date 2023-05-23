/**
 * Test helper functions.
 */

// import * as h from './helper.mjs';
import * as h from '@ibgib/helper-gib';
import { firstOfAll, ifWe, ifWeMight, iReckon, respecfully, respecfullyDear } from '@ibgib/helper-gib/dist/respec-gib/respec-gib.mjs';
const maam = `[${import.meta.url}]`, sir = maam;

import * as c from './constants.mjs';
import * as encryptGib from './encrypt-decrypt.mjs';
import { SaltStrategy, HashAlgorithm } from './types.mjs';

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
const TEST_INITIAL_RECURSIONS = [1, 20];
/**
 * any higher and it goes pretty slow for testing purposes on my machine
 *
 * REMEMBER: This happens **per hex character encrypted/decrypted**.
 */
const TEST_RECURSIONS_PER_HASH = [1, 3];
const TEST_SALTS = [
    ...CHARS_WE_CHAR_ABOUT.slice(0, 2),
    CHARS_WE_CHAR_ABOUT_SINGLE_STRING,
];
const TEST_SALT_STRATEGIES = Object.keys(SaltStrategy).map(x => SaltStrategy[x]);
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

async function initLongData(): Promise<void> {
    for (let i = 0; i < 5; i++) {
        let uuid = await h.getUUID();
        LONG_DATA += uuid + '\n';
    }
    for (let i = 0; i < 10; i++) {
        let uuid = await h.getUUID();
        LONG_SECRET += uuid + '\n';
    }
}
await initLongData();
TEST_DATAS.push(LONG_DATA); // comment this if you don't want a long data test
TEST_SECRETS.push(LONG_SECRET); // comment this if you don't want a long secret test

for (const dataToEncrypt of TEST_DATAS) {
    for (const initialRecursions of TEST_INITIAL_RECURSIONS) {
        for (const recursionsPerHash of TEST_RECURSIONS_PER_HASH) {
            for (const salt of TEST_SALTS) {
                for (const saltStrategy of TEST_SALT_STRATEGIES) {
                    for (const encryptedDataDelimiter of TEST_DELIMITERS) {
                        for (const secret of TEST_SECRETS) {
                            for (const confirm of TEST_CONFIRM_VALUES) {

                                // const hashAlgorithm: HashAlgorithm = 'SHA-256'; // only one hash algorithm for now
                                const hashAlgorithm: HashAlgorithm = 'SHA-512'; // only one hash algorithm for now

                                await respecfully(sir, `enc/dec stress`, async () => {
                                    await ifWe(sir, `${dataToEncrypt.slice(0, 7)}...(${dataToEncrypt.length}),${secret.slice(0, 7)}...(${secret.length}),${initialRecursions},${recursionsPerHash},${salt.slice(0, 7)}(${salt.length}),${saltStrategy},"${encryptedDataDelimiter}",${confirm}`, async () => {

                                        const resEncrypt = await encryptGib.encrypt({
                                            dataToEncrypt,
                                            initialRecursions,
                                            recursionsPerHash,
                                            salt,
                                            saltStrategy,
                                            secret,
                                            hashAlgorithm,
                                            encryptedDataDelimiter,
                                            confirm,
                                        });
                                        if (resEncrypt.errors) {
                                            console.error(resEncrypt.errors.toString())
                                        }
                                        iReckon(sir, resEncrypt).isGonnaBeTruthy();
                                        iReckon(sir, (resEncrypt.errors || []).length).asTo('no errors').isGonnaBe(0);
                                        iReckon(sir, (resEncrypt.warnings || []).length).asTo('no warnings equal').isGonnaBe(0);
                                        iReckon(sir, resEncrypt.encryptedData).asTo('encryptedData').isGonnaBeTruthy();

                                        // console.log(`resEncryptedData.encryptedData.length: ${resEncrypt.encryptedData!.length}`);

                                        const resDecrypt = await encryptGib.decrypt({
                                            encryptedData: resEncrypt.encryptedData!,
                                            initialRecursions,
                                            recursionsPerHash,
                                            salt,
                                            saltStrategy,
                                            secret,
                                            hashAlgorithm,
                                            encryptedDataDelimiter,
                                        });

                                        // console.log(`resEncryptedData.encryptedData:\n${resEncryptedData.encryptedData}`);
                                        iReckon(sir, resDecrypt).isGonnaBeTruthy();
                                        iReckon(sir, (resDecrypt.errors || []).length).asTo('no errors').isGonnaBe(0);
                                        iReckon(sir, (resDecrypt.warnings || []).length).asTo('no warnings equal').isGonnaBe(0);
                                        iReckon(sir, resDecrypt.decryptedData).asTo('decryptedData').isGonnaBeTruthy();

                                        iReckon(sir, resDecrypt.decryptedData).asTo('decryptedData equal dataToEncrypt').isGonnaBe(dataToEncrypt);
                                    });
                                });

                            }
                        }
                    }
                }
            }
        }
    }
} // for..of data test case permutations
