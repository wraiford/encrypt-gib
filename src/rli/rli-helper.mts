import * as pathUtils from 'path';
import { statSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { ReadStream } from 'node:tty';
import * as tty from 'node:tty';
import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process'; // decide if use this or not

import { extractErrorMsg, getTimestampInTicks, getUUID } from '@ibgib/helper-gib/dist/helpers/utils-helper.mjs';

import { ENCRYPT_LOG_A_LOT } from "../constants.mjs";
import {
    ARG_INFO_DATA_PATH, ARG_INFO_DATA_STRING, ARG_INFO_ENCRYPT, ARG_INFO_OUTPUT_PATH, ARG_INFO_SALT, ARG_INFO_STRENGTH, ENCRYPTED_OUTPUT_FILE_EXT
} from "./rli-constants.mjs";
import { ArgInfo, GenericEncryptionStrengthSetting } from "./rli-types.mjs";
import { BaseArgs, EncryptResult } from '../types.mjs';


/**
 * used in verbose logging (across all ibgib libs atow)
 */
const logalot = ENCRYPT_LOG_A_LOT || false;


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


// #region extractArg functions

export async function extractArg_dataToEncrypt({
    argInfos,
}: {
    argInfos: ArgInfo[],
}): Promise<string> {
    const lc = `[${extractArg_dataToEncrypt.name}]`;
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

export function extractArg_strength({ argInfos }: { argInfos: ArgInfo[]; }): GenericEncryptionStrengthSetting {
    const lc = `[${extractArg_strength.name}]`;
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

export async function extractArg_outputPath({
    argInfos,
}: {
    argInfos: ArgInfo[],
}): Promise<string> {
    const lc = `[${extractArg_outputPath.name}]`;
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

        // add file extension only if we're encrypting and it isn't already there
        const isEncrypt = argInfos.some(x => x.name === ARG_INFO_ENCRYPT.name);
        if (isEncrypt && !relOrAbsPath.endsWith(ENCRYPTED_OUTPUT_FILE_EXT)) {
            console.log(`${lc} adding file extension .${ENCRYPTED_OUTPUT_FILE_EXT}`);
            relOrAbsPath += (relOrAbsPath.endsWith('.') ? ENCRYPTED_OUTPUT_FILE_EXT : `.${ENCRYPTED_OUTPUT_FILE_EXT}`);
        }

        return relOrAbsPath;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export async function extractArg_dataPath({
    argInfos,
}: {
    argInfos: ArgInfo[],
}): Promise<string> {
    const lc = `[${extractArg_dataPath.name}]`;
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

export function extractArg_salt({
    argInfos,
}: {
    argInfos: ArgInfo[],
}): string | undefined {
    const lc = `[${extractArg_salt.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 839bf1336c0a46e9bbb32a079fe1d921)`); }

        if (!argInfos.some(x => x.name === ARG_INFO_SALT.name)) {
            throw new Error(`not output path arg provided (E: 7e297223571142dea62679ce4743a2b3)`);
        }

        const argInfo = argInfos.filter(x => x.name === ARG_INFO_SALT.name)[0];
        if (!argInfo.value) { return undefined; /* <<<< returns early */ }

        const salt = argInfo.value! as string;
        return salt;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

// #endregion extractArg functions

export async function getSecretFromUser({
    confirm,
}: {
    confirm: boolean,
}): Promise<string> {
    const lc = `[${getSecretFromUser.name}]`;
    try {
        console.warn(`WARNING: THIS IS NOT IMPLEMENTED CORRECTLY WITH REGARDS TO PRIVACY`);
        const rl = readline.createInterface({
            input: stdin,
            output: stdout
        });
        let secret: string | undefined = undefined;
        try {
            do {
                const secret1 =
                    await rl.question(`enter your secret key for the encryption:\n`);
                if (!secret1) {
                    `no secret provided. please try again.`;
                    continue;
                }
                if (confirm) {
                    const secret2 = await rl.question(`confirm:\n`);
                    if (secret2 === secret1) {
                        secret = secret1;
                    } else {
                        console.log(`secrets do not match. please try again.`);
                    }
                } else {
                    secret = secret1;
                    continue;
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


export async function validateEncryptedFile(encryptResults: EncryptResult): Promise<void> {
    const lc = `[${validateEncryptedFile.name}]`;
    if (!encryptResults) { throw new Error(`encryptResults falsy? (E: dba36cd75b5f894822e7843d98509a23)`); }
    if (!encryptResults.encryptedData) { throw new Error(`encryptedData falsy (E: 7ae0f4ba8e04a644226d02d47e08ed23)`); }
    if (!encryptResults.hashAlgorithm) { throw new Error(`hashAlgorithm not found (E: 7a5fc36d943c20a68fdc464a6d7d6923)`); }
    console.warn(`${lc}[WARNING] flesh out more validation yo (W: 86a6fdaaa87242f18a1b2bbe75ac0b75)`);
}

export async function getBaseArgsSet({
    secret,
    salt,
    strength,
}: {
    secret: string,
    salt: string | undefined,
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
