#!/usr/bin/env node

/**
 * @module rli
 *
 * request line interface - may sound a silly name, but we're moving on from
 * command line interfaces to more flexible, natural language systems, yes? that
 * means things like synonyms and the like, let alone if you're just resorting
 * to an ai model. in which case, why not be polite?
 *
 * This module is for the interpreting of the incoming args when this package is
 * executed from the request line (bash, zsh, etc.).
 *
 * I am leaving this not even remotely finished atow, as this could easily be
 * extended with the given structure by another programmer (or llm probably for
 * that matter).
 */

import * as pathUtils from 'path';
import { execPath, cwd, stdin, stdout } from 'node:process'; // decide if use this or not
import { statSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import * as readline from 'node:readline/promises';

import { decrypt, encrypt } from '../encrypt-decrypt.mjs';
import { extractErrorMsg, getTimestamp, getTimestampInTicks, getUUID, pretty } from '@ibgib/helper-gib';
import { BaseArgs, DecryptArgs, DecryptResult, EncryptResult } from '../types.mjs';

/**
 * used in verbose logging (across all ibgib libs atow)
 */
const logalot = true;

const ENCRYPTED_OUTPUT_FILE_EXT = 'encrypt-gib';

/**
 * i think i have this ArgInfo already implemented elsewhere, and plugged up
 * with lex-gib helper, but i'm on a time crunch here.
 */
interface ArgInfo {
    name: string;
    // synonyms: string[]; // todo
    isFlag: boolean;
    value?: string | number | boolean;
}

const ARG_INFO_HELP: ArgInfo = {
    name: 'help',
    isFlag: true,
}
const ARG_INFO_ENCRYPT: ArgInfo = {
    name: 'encrypt',
    isFlag: false,
}
const ARG_INFO_DECRYPT: ArgInfo = {
    name: 'decrypt',
    isFlag: false,
}
const ARG_INFO_DATA_PATH: ArgInfo = {
    name: 'data-path',
    isFlag: false,
}
const ARG_INFO_OUTPUT_PATH: ArgInfo = {
    name: 'output-path',
    isFlag: false,
}
const ARG_INFO_DATA_STRING: ArgInfo = {
    name: 'data-string',
    isFlag: false,
}
const ARG_INFO_STRENGTH: ArgInfo = {
    name: 'strength',
    isFlag: false,
}

const ARG_INFOS: ArgInfo[] = [
    ARG_INFO_HELP,
    ARG_INFO_ENCRYPT,
    ARG_INFO_DECRYPT,
    ARG_INFO_DATA_PATH,
    ARG_INFO_OUTPUT_PATH,
    ARG_INFO_DATA_STRING,
    ARG_INFO_STRENGTH,
];

export async function execRLI(): Promise<void> {
    const lc = `[${execRLI.name}]`;
    try {
        console.log(`${lc} starting... (I: f8361e3196aa46e5912d821cb22ab7a0)\n`);
        console.log(`${lc} process.execPath: ${execPath}`);
        console.log(`${lc} process.cwd(): ${cwd()}`);
        const args = process.argv?.slice(2) ?? [];
        console.log(`${lc} args.join(' '): ${args.join(' ')}`);
        const validationErrors = validateArgs(args);
        if (!validationErrors) {
            if (args.some(arg => argIs({ arg, argInfo: ARG_INFO_HELP }))) {
                showHelp({ args });
                return;
            }

            console.log(`${lc} here are the args received`);
            for (let i = 0; i < args.length; i++) {
                const arg = args[i];
                console.log(`arg ${i}: ${arg}`);
            }

            await execRequestPlease(args);
        } else {
            console.log(`validationErrors: ${validationErrors}`);
        }
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        console.log(`\n${lc} complete.`);
    }
}

function argIs({
    arg,
    argInfo,
}: {
    arg: string,
    argInfo: ArgInfo,
}): boolean {
    return arg?.replace('--', '').toLowerCase() === argInfo.name.toLowerCase();
}

function showHelp({ args }: { args: string[] }): void {
    const helpMsg = `
    THIS IS INCOMPLETE, STUBBED HELP DOCUMENTATION ATOW. CHECK OUT RLI.MTS AND
    THE LIBRARY ITSELF.

    howdy from encrypt-gib. for now here's how it's gotta be:

    encrypt-gib --encrypt|--decrypt --data-path="abs/or/rel/path/to/file]|--data-string="inline simple msg" --output-path="abs/or/rel/path/to/file" --option="some string" --option2=42 --option3=true --optionFlag

    # quick notes

    * output file is just a json file atow
    * output file will always have the extension .encrypt-gib. if that isn't already
      the extension, it will be added.
    * options are NOT case sensitive.

    # encrypt

    this encrypts the given path or simple message using encrypt-gib's novel
    hash-based, low-magic, hex-level encryption algorithm.

    # decrypt

    this decrypts the given path using encrypt-gib's novel yada yada yada.

    # options

    ## data-path

    ## data-string

    ## strength

    "weaker" | "stronger"

    todo: flesh this out eh

    for now, here are the ARG_INFOS in src and possibly implemented:

${pretty(ARG_INFOS)}

    # examples

    encrypt-gib --encrypt --data-path="./cooldata.md" --output-path="./encrypted-output.encrypt-gib"

    encrypt-gib --encrypt --data-string="inline raw msg" --output-path="./filename_here" --strength="weaker"

    encrypt-gib --decrypt --data-path="./cool-encrypted-data.encrypt-gib"

    THIS IS INCOMPLETE, STUBBED HELP DOCUMENTATION ATOW. CHECK OUT RLI.MTS AND
    THE LIBRARY ITSELF.
    `;
    console.log(helpMsg);
}

/**
 *
 * @returns error string if found, otherwise null
 *
 * @param args
 */
function validateArgs(args: string[]): string | undefined {
    const lc = `[${validateArgs.name}]`;
    let validationErrorIfAny: string | undefined = undefined;
    try {
        console.log(`${lc} starting... (I: 80df65a4871c4fbab44e4f045c1b3010)`);
        if (!args || args.length === 0) { throw new Error(`args required. (E: 6e5ff716def8464b887eda395eaca95d)`); }

        // todo: flesh out args validation
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        validationErrorIfAny = error.message;
    } finally {
        console.log(`\n${lc} complete.`);
        return validationErrorIfAny;
    }
}

/**
 * politely executes the request framed by the validated args.
 *
 * note: atow they're not really validated much.
 */
async function execRequestPlease(args: string[]): Promise<void> {
    const lc = `[${execRLI.name}]`;
    try {
        console.log(`${lc} starting... (I: ea2abd65b8d3401eb9c1db873b5b8a04)`);

        const argsSansDashes = args.map(x => x.slice(2));

        console.log(`argsSansDashes: ${argsSansDashes}`);

        const argInfos = argsSansDashes.map((arg: string) => {
            let name: string;
            let value: string | number | boolean;
            let argInfo: ArgInfo;
            if (arg.includes('=')) {
                [name, value] = arg.split('=');
                argInfo = {
                    name,
                    value,
                    isFlag: false,
                }
            } else {
                name = arg;
                argInfo = {
                    name: arg,
                    isFlag: false,
                }
            }
            return argInfo!;
        });

        if (argInfos.some(x => x.name === 'encrypt')) {
            await execEncrypt({ argInfos });
        } else if (argInfos.some(x => x.name === 'decrypt')) {
            await execDecrypt({ argInfos });
        } else {
            throw new Error(`(UNEXPECTED) either encrypt or decrypt required. validation error should have triggered (E: aadd799d03204cbb9eef9aa9a8473dc6)`);
        }

        for (let i = 0; i < args.length; i++) {
            const arg = args[i];
            console.log(`arg ${i}: ${arg}`);
        }
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        console.log(`\n${lc} complete.`);
    }
}

// #region encrypt

type GenericEncryptionStrengthSetting = 'weaker' | 'stronger';

async function getBaseArgsSet({
    secret,
    salt,
    strength,
}: {
    secret: string,
    salt?: string,
    strength: GenericEncryptionStrengthSetting,
}): Promise<BaseArgs> {
    const lc = `[${getBaseArgsSet.name}]`;
    if (!salt) {
        console.warn(`${lc} generating publicly visible random salt (W: babb0c7eaeef4e33ab8a6e3897624940)`);
        salt = await getUUID();
    }
    if (strength === 'weaker') {
        const args: BaseArgs = {
            secret,
            initialRecursions: 1000,
            salt,
            saltStrategy: 'initialAppend',
            hashAlgorithm: 'SHA-256',
            indexingMode: 'indexOf',
            multipass: undefined,
            recursionsPerHash: 2,
        }
        return args;
    } else if (strength === 'stronger') {
        const args: BaseArgs = {
            secret,
            initialRecursions: 30_000,
            salt,
            saltStrategy: 'prependPerHash',
            hashAlgorithm: 'SHA-512',
            indexingMode: 'lastIndexOf',
            recursionsPerHash: 10,
            multipass: {
                maxPassSectionLength: 1000,
                // every pass is c. 100 in length, so every 10 passes is 1000 characters per character,
                // really selection of this depends on the length of data, but
                // we'll assume it's relatively small data
                numOfPasses: 100,
            }
        }
        return args;
    } else {
        throw new Error(`unknown strength (${strength}) (E: 8eb1c2c865bd0514b8efd2149fb26523)`);
    }
}

async function execEncrypt({ argInfos }: { argInfos: ArgInfo[] }): Promise<void> {
    const lc = `[${execEncrypt.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 6573534041881444ec8baca28c535d23)`); }

        // first ensure we have an output path that we can work with
        // todo: do more validation on output path
        const outputPath = await getOutputPath({ argInfos });
        if (!outputPath) { throw new Error(`was unable to get output data path from the args. (E: 85e4dc233e95174e9183a97a154c9223)`); }

        const secret = await getSecretFromUser();
        const dataToEncrypt = await getDataToEncrypt({ argInfos });
        const strength = getStrengthFromArgs({ argInfos });
        const baseArgs = await getBaseArgsSet({ secret, strength });
        const timerName = `[encrypt]`;
        console.log(`${lc} starting timer for ${timerName}`);
        console.time(timerName);
        const resEncrypt: EncryptResult = await encrypt({
            dataToEncrypt,
            ...baseArgs
        });
        console.timeEnd(timerName);
        if ((resEncrypt.errors ?? []).length > 0) {
            throw new Error(`there were errors (E: 9dcdca9a704da976473ce396c8047123):\n${resEncrypt.errors!}`);
        }
        if ((resEncrypt.warnings ?? []).length > 0) {
            console.warn(`${lc} WARNING encryption result had warnings (W: 881c99cf92cc403d828b111317de6c25):\n${resEncrypt.warnings!}`);
        }

        const stringifiedJson = JSON.stringify(resEncrypt);
        await writeFile(outputPath, stringifiedJson);
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export async function getOutputPath({
    argInfos,
}: {
    argInfos: ArgInfo[],
}): Promise<string> {
    const lc = `[${getOutputPath.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 0602544df47c3d8ec4201804657c9223)`); }

        if (!argInfos.some(x => x.name === ARG_INFO_OUTPUT_PATH.name)) {
            throw new Error(`not output path arg provided (E: 343f869cf386c3162702d4f5955e0323)`);
        }

        const argInfo = argInfos.filter(x => x.name === ARG_INFO_OUTPUT_PATH.name)[0];
        if (!argInfo.value) {
            throw new Error(`(UNEXPECTED) output path arg found but value is falsy? (E: d8980a9ee032f093d1dac84706611f23)`);
        }

        let relOrAbsPath = argInfo.value! as string;

        const stat = statSync(relOrAbsPath, { throwIfNoEntry: false });
        if (stat === undefined) {
            // no existing file or folder of this path, so we're good
        } else if (stat.isFile()) {
            throw new Error(`data output path is a file that already exists. overwriting ain't happening yet (E: bd047a17a54147c2a851e841bee802dc)`);
        } else if (stat.isDirectory()) {
            const filename = getTimestampInTicks() + (await getUUID()).slice(0, 6);
            console.warn(`${lc}[WARNING] data output path is an existing directory. autogenerated filename: ${filename}`);
            relOrAbsPath = pathUtils.join(relOrAbsPath, filename);
        }

        if (!relOrAbsPath.endsWith(ENCRYPTED_OUTPUT_FILE_EXT)) {
            console.log(`${lc} adding file extension .${ENCRYPTED_OUTPUT_FILE_EXT}`);
            relOrAbsPath += `.${ENCRYPTED_OUTPUT_FILE_EXT}`;
        }

        return relOrAbsPath;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export async function getDataPath({
    argInfos,
}: {
    argInfos: ArgInfo[],
}): Promise<string> {
    const lc = `[${getDataPath.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: c2208d316e854be4a1d3a905d62c718a)`); }

        if (!argInfos.some(x => x.name === ARG_INFO_DATA_PATH.name)) {
            throw new Error(`not output path arg provided (E: 53650a263b2843b18a69f772464019e0)`);
        }

        const argInfo = argInfos.filter(x => x.name === ARG_INFO_DATA_PATH.name)[0];
        if (!argInfo.value) {
            throw new Error(`(UNEXPECTED) data path arg found but value is falsy? (E: 4dda29a594584d548765a3123a4ef65b)`);
        }

        let relOrAbsPath = argInfo.value! as string;

        const stat = statSync(relOrAbsPath, { throwIfNoEntry: false });
        if (stat === undefined) {
            // no existing file or folder of this path, so we're good
            throw new Error(`data path not found. path: ${relOrAbsPath} (E: 541933e33ca34426805cf0e54a0608e6)`)
        } else if (stat.isFile()) {
            // good, it's a file
        } else if (stat.isDirectory()) {
            throw new Error(`data path is a directory. it should be a file. (E: 0d9887b1b1a4351f7c34203189b02323)`);
        }

        return relOrAbsPath;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export async function tryRead({
    relOrAbsPath,
}: {
    relOrAbsPath: string,
}): Promise<string | undefined> {
    const lc = `[${tryRead.name}]`;
    try {
        const stat = statSync(relOrAbsPath);
        if (!stat.isFile()) { throw new Error(`path provided is not a file. (${relOrAbsPath}) (E: f295b7e925534546819edfef9a750164)`); }
        const resRead = await readFile(relOrAbsPath, { encoding: 'utf8' as BufferEncoding });
        if (logalot) {
            console.log(`${lc} record found. data length: ${resRead?.length ?? 0}. fullPath: ${relOrAbsPath}  (I: aa81b3d01e9542788b07302dd174c03d)`);
            // console.dir(resRead)
        }
        return resRead;
    } catch (error) {
        if (logalot) { console.log(`${lc} path not found (${relOrAbsPath})\nerror:\n${extractErrorMsg(error)} (I: 6658a0b81d3249d2aefc8e3d28efa87b)`); }
        return undefined;
    } finally {
        if (logalot) { console.log(`${lc} complete. (I: 747a187ca6234dd4b2bf9a11a87a0d91)`); }
    }
}

export async function getDataToEncrypt({
    argInfos,
}: {
    argInfos: ArgInfo[],
}): Promise<string> {
    const lc = `[${getDataToEncrypt.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 656ba405a9b42769d50d67e651b84823)`); }
        let resDataToEncrypt: string | undefined = undefined;

        if (argInfos.some(x => x.name === ARG_INFO_DATA_PATH.name)) {
            const argInfo = argInfos.filter(x => x.name === ARG_INFO_DATA_PATH.name)[0];
            if (!argInfo.value) { throw new Error(`data path argInfo.value is falsy (E: 8ee94fe777615cac74aca495a5e2d923)`); }
            resDataToEncrypt = await tryRead({ relOrAbsPath: argInfo.value! as string });
        } else if (argInfos.some(x => x.name === ARG_INFO_DATA_STRING.name)) {
            const argInfo = argInfos.filter(x => x.name === ARG_INFO_DATA_STRING.name)[0];
            if (!argInfo.value) { throw new Error(`data path argInfo.value is falsy (E: e201fd0f95a641418bb735eb43a38c0b)`); }
            resDataToEncrypt = argInfo.value! as string;
        } else {
            throw new Error(`(UNEXPECTED) encrypt chosen but neither data path nor data string provided? validation should have caught this. (E: c238fa6aab12684bc1582e618977a623)`);
        }

        if (!resDataToEncrypt) { throw new Error(`could not get dataToEncrypt (E: 36ce341bc5b45394fbc97fab808d3823)`); }

        return resDataToEncrypt;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

// #endregion encrypt


// #region decrypt

async function execDecrypt({ argInfos }: { argInfos: ArgInfo[] }): Promise<void> {
    const lc = `[${execDecrypt.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: a45ae2cd4767411fbdea64ecc182ac93)`); }

        // first ensure we have an output path that we can work with
        // todo: do more validation on output path
        const outputPath = await getOutputPath({ argInfos });
        if (!outputPath) { throw new Error(`was unable to get output data path from the args. (E: a9d0142b366a42a3b4e19332e63b10620)`); }

        const dataPath = await getDataPath({ argInfos });
        const encryptFileContents_JSON_atow = await tryRead({ relOrAbsPath: dataPath });
        if (!encryptFileContents_JSON_atow) { throw new Error(`could not read file? dataPath: ${dataPath} (E: 16b5daf66b4f1c3fc83dbdf9bdcc0823)`); }

        if (logalot) { console.log(`${lc} parsing encrypted file json (I: 9fc96269470322f689e901ab1eef5523)`); }
        const fileContents = JSON.parse(encryptFileContents_JSON_atow) as DecryptArgs;

        // todo: validate the file
        await validateEncryptedFile(fileContents);

        const secret = await getSecretFromUser();
        fileContents.secret = secret!;

        const timerName = `[decrypt]`;
        console.log(`${lc} starting timer for ${timerName}`);
        console.time(timerName);
        const resDecrypt: DecryptResult = await decrypt(fileContents);
        console.timeEnd(timerName);
        if ((resDecrypt.errors ?? []).length > 0) {
            throw new Error(`there were errors (E: a3bb397a5b02439a95cc878a376c150b):\n${resDecrypt.errors!}`);
        }
        if ((resDecrypt.warnings ?? []).length > 0) {
            console.warn(`${lc} WARNING encryption result had warnings (W: 1b68358ca7ef4854bee196272f34e164):\n${resDecrypt.warnings!}`);
        }

        if (!resDecrypt.decryptedData) { throw new Error(`decryptedData falsy? (E: 0dfab9f2e3351535c750f7d810465b23)`); }

        if (logalot) { console.log(`${lc} writing to file... (I: 509956939a9825609b43f2572e856a23)`); }
        await writeFile(outputPath, resDecrypt.decryptedData);
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

// #endregion decrypt

// #region common

export async function getSecretFromUser(): Promise<string> {
    const lc = `[${getSecretFromUser.name}]`;
    try {
        console.warn(`WARNING: THIS MAY NOT BE IMPLEMENTED CORRECTLY WITH REGARDS TO PRIVACY IN LINUX (TIME CRUNCH)`);

        const rl = readline.createInterface({ input: stdin, output: stdout });
        let secret: string | undefined = undefined;
        try {
            do {
                const secret1 =
                    await rl.question(`enter your secret key for the encryption:\n`);
                if (!secret1) {
                    `no secret provided. please try again.`;
                    continue;
                }
                const secret2 =
                    await rl.question(`confirm:\n`);
                if (secret2 === secret1) {
                    secret = secret1;
                } else {
                    console.log(`secrets do not match. please try again.`);
                }
            } while (!secret);
            return secret;
        } catch (error) {
            throw error;
        } finally {
            rl.close();
        }
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}

function getStrengthFromArgs({ argInfos }: { argInfos: ArgInfo[]; }): GenericEncryptionStrengthSetting {
    const lc = `[${getStrengthFromArgs.name}]`;
    let resStrength: GenericEncryptionStrengthSetting = 'stronger'; // default
    if (argInfos.some(x => x.name === ARG_INFO_STRENGTH.name)) {
        const argInfo = argInfos.filter(x => x.name === ARG_INFO_STRENGTH.name)[0]!;
        if (['stronger', 'weaker'].includes(argInfo.value as string)) {
            resStrength = argInfo.value! as GenericEncryptionStrengthSetting;
        } else {
            console.warn(`${lc}[WARNING] strength arg present but not valid. only "stronger" and "weaker" atow. defaulting to ${resStrength} (W: 979262e68df54b5a9aadcf514c7b54ad)`);
        }
    } else {
        console.log(`${lc} defaulting strength to: ${resStrength} (W: 979262e68df54b5a9aadcf514c7b54ad)`);
    }
    return resStrength;
}

async function validateEncryptedFile(encryptResults: EncryptResult): Promise<void> {
    const lc = `[${validateEncryptedFile.name}]`;
    if (!encryptResults) { throw new Error(`encryptResults falsy? (E: dba36cd75b5f894822e7843d98509a23)`); }
    if (!encryptResults.encryptedData) { throw new Error(`encryptedData falsy (E: 7ae0f4ba8e04a644226d02d47e08ed23)`); }
    if (!encryptResults.hashAlgorithm) { throw new Error(`hashAlgorithm not found (E: 7a5fc36d943c20a68fdc464a6d7d6923)`); }
    if (!encryptResults.indexingMode) { throw new Error(`indexingMode not found (E: 0d4fcd3bb68d80554220f4de0c5e6823)`); }
    console.warn(`${lc}[WARNING] flesh out more validation yo (W: 86a6fdaaa87242f18a1b2bbe75ac0b75)`);
}

// #endregion common
await execRLI();
