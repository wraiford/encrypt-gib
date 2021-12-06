/**
 * Test helper functions.
 */

import { expect } from 'chai';
import * as h from './helper';
import * as c from './constants';
import * as encryptGib from './encrypt-decrypt';
import { SaltStrategy, HashAlgorithm } from './types';

const SIMPLEST_DATA = 'a';
/**
 * Just looking to do some basic characters, not all unicode (not my specialty).
 */
const CHARS_WE_CHAR_ABOUT_SINGLE_STRING = `abcdefghijklmnopqrstuvwxyz\`1234567890-=ABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+,./;'[]\\<>?:"{}|`;
const CHARS_WE_CHAR_ABOUT = [];
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
const TEST_INITIAL_RECURSIONS = [0,1,20000];
/**
 * any higher and it goes pretty slow for testing purposes on my machine
 *
 * REMEMBER: This happens **per hex character encrypted/decrypted**.
 */
const TEST_RECURSIONS_PER_HASH = [1,15];
const TEST_SALTS = [
    ...CHARS_WE_CHAR_ABOUT.slice(0,2),
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

async function initData(): Promise<void> {
    for (let i = 0; i < 50; i++) {
        let uuid = await h.getUUID();
        LONG_DATA += uuid + '\n';
    }
    for (let i = 0; i < 100; i++) {
        let uuid = await h.getUUID();
        LONG_SECRET += uuid + '\n';
    }
}

describe(`encrypting & decrypting`, () => {

    describe(`stress testing... (not-so-"unit"-testy)`, async () => {
        await initData();

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

            it(`enc<->dec,${dataToEncrypt.slice(0, 7)}...(${dataToEncrypt.length}),${secret.slice(0, 7)}...(${secret.length}),${initialRecursions},${recursionsPerHash},${salt.slice(0,7)}(${salt.length}),${saltStrategy},"${encryptedDataDelimiter}",${confirm}`, async () => {

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
                expect(resEncrypt).to.not.be.undefined;
                expect(resEncrypt).to.not.be.null;
                expect((resEncrypt.errors || []).length).to.equal(0, 'no errors');
                expect((resEncrypt.warnings || []).length).to.equal(0, 'no warnings equal');
                expect(resEncrypt.encryptedData, 'encryptedData').to.not.be.undefined;
                expect(resEncrypt.encryptedData, 'encryptedData').to.not.be.null;

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
                expect(resDecrypt).to.not.be.undefined;
                expect(resDecrypt).to.not.be.null;
                expect((resDecrypt.errors || []).length).to.equal(0, 'no errors');
                expect((resDecrypt.warnings || []).length).to.equal(0, 'no warnings equal');
                expect(resDecrypt.decryptedData, 'decryptedData').to.not.be.undefined;
                expect(resDecrypt.decryptedData, 'decryptedData').to.not.be.null;

                expect(resDecrypt.decryptedData).to.equal(dataToEncrypt, 'decryptedData equal dataToEncrypt');
            });

        }}}}}}}} // for..of data test case permutations
    });
});