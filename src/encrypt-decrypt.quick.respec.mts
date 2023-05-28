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
    CHARS_WE_CHAR_ABOUT_SINGLE_STRING,
    // ...CHARS_WE_CHAR_ABOUT, // takes awhile, adds lots of test permutations
];

// const TEST_SALT_STRATEGIES = Object.keys(SaltStrategy).map(x => SaltStrategy[x]);
const TEST_SALT_STRATEGIES: SaltStrategy[] = [
    SaltStrategy.appendPerHash,
    SaltStrategy.initialAppend,
];
const TEST_CONFIRM_VALUES: boolean[] = [true, false];

async function initLongData(): Promise<void> {
    for (let i = 0; i < 2; i++) {
        let uuid = await h.getUUID();
        LONG_DATA += uuid + '\n';
    }
}
await initLongData();
TEST_DATAS.push(LONG_DATA); // comment this if you don't want a long data test

const encryptedDataDelimiter = c.DEFAULT_ENCRYPTED_DATA_DELIMITER;
const secret = 'great pw here (jk)';
const hashAlgorithm = HashAlgorithm.sha_256;
const salt = 'salt here yo';
const initialRecursions = 5;
const confirm = false;
const recursionsPerHash = 3;

for (const dataToEncrypt of TEST_DATAS) {
    for (const saltStrategy of TEST_SALT_STRATEGIES) {

        await respecfully(sir, `enc/dec quick`, async () => {
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
} // for..of data test case permutations
