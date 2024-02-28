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

import { execPath, cwd, } from 'node:process';
import { writeFile } from 'node:fs/promises';

import { pretty, extractErrorMsg } from '@ibgib/helper-gib/dist/helpers/utils-helper.mjs';
import { RCLIArgInfo, RCLIArgType, } from "@ibgib/helper-gib/dist/rcli/rcli-types.mjs";
import { buildArgInfos, argIs, } from "@ibgib/helper-gib/dist/rcli/rcli-helper.mjs";
import { PARAM_INFO_HELP } from "@ibgib/helper-gib/dist/rcli/rcli-constants.mjs";
import { tryRead_node, promptForSecret_node } from "@ibgib/helper-gib/dist/helpers/node-helper.mjs";

import { decrypt, encrypt } from '../encrypt-decrypt.mjs';
import { DecryptArgs, DecryptResult, EncryptResult } from '../types.mjs';
import { ENCRYPT_LOG_A_LOT } from '../constants.mjs';
import { PARAM_INFOS, } from './rcli-constants.mjs';
import {
    extractArg_dataPath, extractArg_dataToEncrypt, extractArg_hashAlgorithm,
    extractArg_indexingMode, extractArg_initialRecursions, extractArg_blockMode, extractArg_outputPath,
    extractArg_salt, extractArg_saltStrategy, extractArg_strength, getBaseArgsSet,
    validateEncryptedFile,
    extractArg_recursionsPerHash,
} from './rcli-helper.mjs';

/**
 * used in verbose logging (across all ibgib libs atow)
 */
const logalot = ENCRYPT_LOG_A_LOT || false;


export async function execRCLI(): Promise<void> {
    const lc = `[${execRCLI.name}]`;
    try {
        console.log(`${lc} starting... (I: f8361e3196aa46e5912d821cb22ab7a0)\n`);
        console.log(`${lc} process.execPath: ${execPath}`);
        console.log(`${lc} process.cwd(): ${cwd()}`);
        const args = process.argv?.slice(2) ?? [];
        console.log(`${lc} args.join(' '): ${args.join(' ')}`);
        const validationErrors = validateArgs(args);
        if (!validationErrors) {
            if (args.some(arg => argIs({ arg, paramInfo: PARAM_INFO_HELP }))) {
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
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        console.log(`\n${lc} complete.`);
    }
}

// function argIs({
//     arg,
//     argInfo,
// }: {
//     arg: string,
//     argInfo: RCLIArgInfo,
// }): boolean {
//     return arg?.replace('--', '').toLowerCase() === argInfo.name.toLowerCase();
// }

function showHelp({ args }: { args: string[] }): void {
    const helpMsg = `
    THIS IS INCOMPLETE, STUBBED HELP DOCUMENTATION ATOW. CHECK OUT RCLI.MTS AND
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

    for now, here are the PARAM_INFOS in src and possibly implemented:

${pretty(PARAM_INFOS)}

    # examples

    encrypt-gib --encrypt --data-path="./cooldata.md" --output-path="./encrypted-output.encrypt-gib"

    encrypt-gib --encrypt --data-string="inline raw msg" --output-path="./filename_here" --strength="weaker"

    encrypt-gib --decrypt --data-path="./cool-encrypted-data.encrypt-gib"

    THIS IS INCOMPLETE, STUBBED HELP DOCUMENTATION ATOW. CHECK OUT RCLI.MTS AND
    THE LIBRARY ITSELF. ATOW ALL NON-FLAG PARAMETER VALUES MUST BE IN DOUBLE QUOTES.

    atow I use the following in encrypt-gib's root dir (NOTE: "stronger" setting may take a LONG time):
    node . --encrypt --data-string="inline raw msg" --output-path="./ciphertext_file" --strength="weaker"
    node . --encrypt --data-path="./plaintext_file.md" --output-path="./ciphertext_file" --strength="stronger"
    node . --decrypt --data-path="./ciphertext_file.encrypt-gib" --output-path="./deciphered_file.md"

    `;
    console.log(helpMsg);
}

/**
 * stubbed validation function. there is also validation
 * when building the arg info objects.
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
        console.error(`${lc} ${extractErrorMsg(error)}`);
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
    const lc = `[${execRCLI.name}]`;
    try {
        console.log(`${lc} starting... (I: ea2abd65b8d3401eb9c1db873b5b8a04)`);

        const argsSansDashes = args.map(x => x.slice(2));

        console.log(`argsSansDashes: ${argsSansDashes}`);

        const argInfos = buildArgInfos({ args, paramInfos: PARAM_INFOS, logalot });

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
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        console.log(`\n${lc} complete.`);
    }
}

async function execEncrypt({ argInfos }: { argInfos: RCLIArgInfo<RCLIArgType>[] }): Promise<void> {
    const lc = `[${execEncrypt.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 6573534041881444ec8baca28c535d23)`); }

        // first ensure we have an output path that we can work with
        // todo: do more validation on output path
        const outputPath = await extractArg_outputPath({ argInfos });
        if (!outputPath) { throw new Error(`was unable to get output data path from the args. (E: 85e4dc233e95174e9183a97a154c9223)`); }

        const secret = await promptForSecret_node({ confirm: true });
        const dataToEncrypt = await extractArg_dataToEncrypt({ argInfos });
        const strength = extractArg_strength({ argInfos });
        const salt = extractArg_salt({ argInfos });
        const indexingMode = extractArg_indexingMode({ argInfos });
        const blockMode = extractArg_blockMode({ argInfos });
        const hashAlgorithm = extractArg_hashAlgorithm({ argInfos });
        const saltStrategy = extractArg_saltStrategy({ argInfos });
        const initialRecursions = extractArg_initialRecursions({ argInfos });
        const recursionsPerHash = extractArg_recursionsPerHash({ argInfos });
        const baseArgs = await getBaseArgsSet({
            secret, strength,
            salt, saltStrategy,
            hashAlgorithm, initialRecursions, recursionsPerHash,
            indexingMode,
            blockMode,
        });
        console.log(`${lc} starting timer`);
        console.time(lc);
        const resEncrypt: EncryptResult = await encrypt({
            dataToEncrypt,
            ...baseArgs
        });
        console.timeEnd(lc);
        if ((resEncrypt.errors ?? []).length > 0) {
            throw new Error(`there were errors (E: 9dcdca9a704da976473ce396c8047123):\n${resEncrypt.errors!}`);
        }
        if ((resEncrypt.warnings ?? []).length > 0) {
            console.warn(`${lc} WARNING encryption result had warnings (W: 881c99cf92cc403d828b111317de6c25):\n${resEncrypt.warnings!}`);
        }

        const stringifiedJson = JSON.stringify(resEncrypt);
        await writeFile(outputPath, stringifiedJson);
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

async function execDecrypt({ argInfos }: { argInfos: RCLIArgInfo<RCLIArgType>[] }): Promise<void> {
    const lc = `[${execDecrypt.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: a45ae2cd4767411fbdea64ecc182ac93)`); }

        // first ensure we have an output path that we can work with
        // todo: do more validation on output path
        const outputPath = await extractArg_outputPath({ argInfos });
        if (!outputPath) { throw new Error(`was unable to get output data path from the args. (E: a9d0142b366a42a3b4e19332e63b10620)`); }

        const dataPath = await extractArg_dataPath({ argInfos });
        const encryptFileContents_JSON_atow = await tryRead_node({ relOrAbsPath: dataPath });
        if (!encryptFileContents_JSON_atow) { throw new Error(`could not read file? dataPath: ${dataPath} (E: 16b5daf66b4f1c3fc83dbdf9bdcc0823)`); }

        if (logalot) { console.log(`${lc} parsing encrypted file json (I: 9fc96269470322f689e901ab1eef5523)`); }
        const fileContents = JSON.parse(encryptFileContents_JSON_atow) as DecryptArgs;

        // todo: validate the file
        await validateEncryptedFile(fileContents);

        const secret = await promptForSecret_node({ confirm: false });
        fileContents.secret = secret!;

        console.log(`${lc} starting timer`);
        console.time(lc);
        const resDecrypt: DecryptResult = await decrypt(fileContents);
        console.timeEnd(lc);
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
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

await execRCLI();
