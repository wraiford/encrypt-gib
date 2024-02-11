import * as pathUtils from 'path';
import { statSync } from 'node:fs';
import { readFile, } from 'node:fs/promises';
import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process'; // decide if use this or not

import { extractErrorMsg, getTimestampInTicks, getUUID, pretty } from '@ibgib/helper-gib/dist/helpers/utils-helper.mjs';
import {
    PARAM_INFO_DATA_PATH,
    PARAM_INFO_DATA_STRING,
    PARAM_INFO_OUTPUT_PATH,
} from "@ibgib/helper-gib/dist/rcli/rcli-constants.mjs";
import { RCLIArgInfo, RCLIArgType, RCLIParamInfo, } from "@ibgib/helper-gib/dist/rcli/rcli-types.mjs";
import { } from "@ibgib/helper-gib/dist/rcli/rcli-helper.mjs";
import { tryRead_node } from "@ibgib/helper-gib/dist/helpers/node-helper.mjs";

import { DEFAULT_MAX_BLOCK_SIZE, DEFAULT_NUM_OF_PASSES, ENCRYPT_LOG_A_LOT } from "../constants.mjs";
import {
    PARAM_INFO_ENCRYPT, PARAM_INFO_SALT, PARAM_INFO_STRENGTH, ENCRYPTED_OUTPUT_FILE_EXT,
    PARAM_INFO_INDEXING_MODE, PARAM_INFO_BLOCKMODE_FLAG,
    PARAM_INFO_BLOCKMODE_BLOCK_SIZE, PARAM_INFO_BLOCKMODE_NUM_OF_PASSES, PARAM_INFO_HASH_ALGORITHM,
    PARAM_INFO_SALT_STRATEGY, PARAM_INFO_INITIAL_RECURSIONS
} from "./rcli-constants.mjs";
import { GenericEncryptionStrengthSetting, } from "./rcli-types.mjs";
import {
    ALPHABET_INDEXING_MODES, AlphabetIndexingMode, BaseArgs, EncryptResult,
    HASH_ALGORITHMS, HashAlgorithm, BlockModeOptions, SALT_STRATEGIES, SaltStrategy
} from '../types.mjs';


/**
 * used in verbose logging
 */
const logalot = ENCRYPT_LOG_A_LOT || false;


// export async function tryRead({
//     relOrAbsPath,
// }: {
//     relOrAbsPath: string,
// }): Promise<string | undefined> {
//     const lc = `[${tryRead.name}]`;
//     try {
//         const stat = statSync(relOrAbsPath);
//         if (!stat.isFile()) { throw new Error(`path provided is not a file. (${relOrAbsPath}) (E: f295b7e925534546819edfef9a750164)`); }
//         const resRead = await readFile(relOrAbsPath, { encoding: 'utf8' as BufferEncoding });
//         if (logalot) {
//             console.log(`${lc} record found. data length: ${resRead?.length ?? 0}. fullPath: ${relOrAbsPath}  (I: aa81b3d01e9542788b07302dd174c03d)`);
//         }
//         return resRead;
//     } catch (error) {
//         if (logalot) { console.log(`${lc} path not found (${relOrAbsPath})\nerror:\n${extractErrorMsg(error)} (I: 6658a0b81d3249d2aefc8e3d28efa87b)`); }
//         return undefined;
//     } finally {
//         if (logalot) { console.log(`${lc} complete. (I: 747a187ca6234dd4b2bf9a11a87a0d91)`); }
//     }
// }

// #region extractArg functions

export async function extractArg_dataToEncrypt({
    argInfos,
}: {
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): Promise<string> {
    const lc = `[${extractArg_dataToEncrypt.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 656ba405a9b42769d50d67e651b84823)`); }
        let resDataToEncrypt: string | undefined = undefined;

        let dataPath = extractArgValue({ paramInfo: PARAM_INFO_DATA_PATH, argInfos }) as string | undefined;
        if (dataPath) {
            // data path given, so load from the path
            resDataToEncrypt = await tryRead_node({ relOrAbsPath: dataPath });
        } else {
            // data path not given, so should have raw data string
            resDataToEncrypt = extractArgValue({ paramInfo: PARAM_INFO_DATA_STRING, argInfos }) as string | undefined;
        }

        if (!resDataToEncrypt) { throw new Error(`could not get dataToEncrypt (E: 36ce341bc5b45394fbc97fab808d3823)`); }
        return resDataToEncrypt;
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export function extractArg_strength({ argInfos }: { argInfos: RCLIArgInfo<RCLIArgType>[]; }): GenericEncryptionStrengthSetting {
    const lc = `[${extractArg_strength.name}]`;
    let resStrength: GenericEncryptionStrengthSetting = 'stronger'; // default

    const strength =
        extractArgValue({ paramInfo: PARAM_INFO_STRENGTH, argInfos }) as string | undefined;
    if (strength) {
        if (['stronger', 'weaker'].includes(strength)) {
            resStrength = strength as GenericEncryptionStrengthSetting;
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
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): Promise<string> {
    const lc = `[${extractArg_outputPath.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 0602544df47c3d8ec4201804657c9223)`); }

        if (!argInfos.some(x => x.name === PARAM_INFO_OUTPUT_PATH.name)) {
            throw new Error(`not output path arg provided (E: 343f869cf386c3162702d4f5955e0323)`);
        }

        const argInfo = argInfos.filter(x => x.name === PARAM_INFO_OUTPUT_PATH.name)[0];
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
        const isEncrypt = argInfos.some(x => x.name === PARAM_INFO_ENCRYPT.name);
        if (isEncrypt && !relOrAbsPath.endsWith(ENCRYPTED_OUTPUT_FILE_EXT)) {
            console.log(`${lc} adding file extension .${ENCRYPTED_OUTPUT_FILE_EXT}`);
            relOrAbsPath += (relOrAbsPath.endsWith('.') ? ENCRYPTED_OUTPUT_FILE_EXT : `.${ENCRYPTED_OUTPUT_FILE_EXT}`);
        }

        return relOrAbsPath;
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export async function extractArg_dataPath({
    argInfos,
}: {
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): Promise<string> {
    const lc = `[${extractArg_dataPath.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: c2208d316e854be4a1d3a905d62c718a)`); }

        // if (!argInfos.some(x => x.name === PARAM_INFO_DATA_PATH.name)) {
        //     throw new Error(`not output path arg provided (E: 53650a263b2843b18a69f772464019e0)`);
        // }

        // const argInfo = argInfos.filter(x => x.name === PARAM_INFO_DATA_PATH.name)[0];
        // if (!argInfo.value) {
        //     throw new Error(`(UNEXPECTED) data path arg found but value is falsy? (E: 4dda29a594584d548765a3123a4ef65b)`);
        // }

        // let relOrAbsPath = argInfo.value! as string;
        const relOrAbsPath = extractArgValue({ paramInfo: PARAM_INFO_DATA_PATH, argInfos, throwIfNotFound: true }) as string;

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
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export function extractArg_salt({
    argInfos,
}: {
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): string | undefined {
    const lc = `[${extractArg_salt.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 839bf1336c0a46e9bbb32a079fe1d921)`); }

        const salt = extractArgValue({ paramInfo: PARAM_INFO_SALT, argInfos }) as string | undefined;
        return salt;
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export function extractArg_indexingMode({
    argInfos,
}: {
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): AlphabetIndexingMode | undefined {
    const lc = `[${extractArg_indexingMode.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 2a761049c6494a429a749a06573793ef)`); }

        const indexingModeRaw = extractArgValue({ paramInfo: PARAM_INFO_INDEXING_MODE, argInfos }) as string | undefined;

        if (indexingModeRaw) {
            if (!ALPHABET_INDEXING_MODES.includes(indexingModeRaw as AlphabetIndexingMode)) {
                throw new Error(`unknown indexingMode: ${indexingModeRaw}. Must be one of: ${ALPHABET_INDEXING_MODES.join(", ")} (E: 107a4f075cfff0fdd5305908c8026623)`);
            }
            return indexingModeRaw as AlphabetIndexingMode;
        } else {
            return undefined;
        }
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export function extractArg_blockMode({
    argInfos,
}: {
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): BlockModeOptions | undefined {
    const lc = `[${extractArg_blockMode.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 965c3f7914054754a678767eae1d1afd)`); }

        const blockMode = extractArgValue({ paramInfo: PARAM_INFO_BLOCKMODE_FLAG, argInfos }) as boolean | undefined;
        if (!blockMode) { return undefined; /* <<<< returns early */ }

        let maxBlockSize = extractArgValue({
            paramInfo: PARAM_INFO_BLOCKMODE_BLOCK_SIZE,
            argInfos,
        }) as number | undefined;
        if (maxBlockSize === 0) { throw new Error(`max section length cannot be 0 (E: e76c559f00d24401ead8cf23649a4523)`); }
        if (maxBlockSize) {
            if (!Number.isInteger(maxBlockSize)) { throw new Error(`invalid maxBlockSize (${maxBlockSize}). must be a valid integer (E: 66da0180dcb7f2fc0a57e47c8e230223)`); }
        } else {
            console.warn(`${lc} maxBlockSize not specified. using default ${DEFAULT_MAX_BLOCK_SIZE}. (W: 8e7a702553564c0ab8e578d34ce204ff)`);
            maxBlockSize = DEFAULT_MAX_BLOCK_SIZE;
        }
        let numOfPasses = extractArgValue({
            paramInfo: PARAM_INFO_BLOCKMODE_NUM_OF_PASSES,
            argInfos,
        }) as number | undefined;
        if (numOfPasses === 0) { throw new Error(`numOfPasses cannot be 0 (E: a6c7c54acf9045a5b0567ab7a78b15c1)`); }
        if (numOfPasses) {
            if (!Number.isInteger(numOfPasses)) { throw new Error(`invalid numOfPasses (${numOfPasses}). must be a valid integer (E: bbe19aab3a9c4277b4aa53a693d83398)`); }
        } else {
            console.warn(`${lc} numOfPasses not specified. using default ${DEFAULT_NUM_OF_PASSES} (W: 398983d673234ffb933eec64334fc806)`);
            numOfPasses = DEFAULT_NUM_OF_PASSES;
        }

        const resBlockModeOptions: BlockModeOptions = {
            maxBlockSize,
            numOfPasses,
        };

        if (logalot) { console.log(`${lc} resBlockModeOptions: ${pretty(resBlockModeOptions)} (I: e9e1ee59a99ce2e7c614ff0663a5d323)`); }

        return resBlockModeOptions;
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export function extractArg_hashAlgorithm({
    argInfos,
}: {
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): HashAlgorithm | undefined {
    const lc = `[${extractArg_hashAlgorithm.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 6f42818e6a7a4c05a3d8a3da8e625598)`); }

        const hashAlgorithm = extractArgValue({ paramInfo: PARAM_INFO_HASH_ALGORITHM, argInfos }) as string | undefined;

        if (hashAlgorithm) {
            if (!HASH_ALGORITHMS.includes(hashAlgorithm as HashAlgorithm)) {
                throw new Error(`unknown hashAlgorithm: ${hashAlgorithm}. Must be one of: ${HASH_ALGORITHMS.join(", ")} (E: dae1ceaf6bfd4f82b9342a51c37ab1b2)`);
            }
            return hashAlgorithm as HashAlgorithm;
        } else {
            return undefined;
        }
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export function extractArg_saltStrategy({
    argInfos,
}: {
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): SaltStrategy | undefined {
    const lc = `[${extractArg_saltStrategy.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: dd727da94f2b410ebb1fa87a6213f3c5)`); }

        const saltStrategy = extractArgValue({ paramInfo: PARAM_INFO_SALT_STRATEGY, argInfos }) as string | undefined;

        if (saltStrategy) {
            if (!SALT_STRATEGIES.includes(saltStrategy as SaltStrategy)) {
                throw new Error(`unknown saltStrategy: ${saltStrategy}. Must be one of: ${SALT_STRATEGIES.join(", ")} (E: dae1ceaf6bfd4f82b9342a51c37ab1b2)`);
            }
            return saltStrategy as SaltStrategy;
        } else {
            return undefined;
        }
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

export function extractArg_initialRecursions({
    argInfos,
}: {
    argInfos: RCLIArgInfo<RCLIArgType>[],
}): number | undefined {
    const lc = `[${extractArg_initialRecursions.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 336f7c30c8f142288b6b66dddf2e4f9a)`); }

        const initialRecursions = extractArgValue({ paramInfo: PARAM_INFO_INITIAL_RECURSIONS, argInfos }) as number | undefined;

        if (initialRecursions && typeof initialRecursions !== 'number') {
            throw new Error(`(UNEXPECTED) initialRecursions expected to be a number at this point. (E: 8f31c7c7492b508a09e801e52775c323)`);
        } else if (initialRecursions === 0) {
            throw new Error(`initialRecursions cannot be 0. Must be a positive integer. (E: 1f312b78a1f384f97d97471923bcbc23)`);
        } else if (initialRecursions) {
            return initialRecursions;
        } else {
            return undefined;
        }
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

/**
 * extracts the arg value(s) from the given `argInfos` that correspond to the
 * given `paramInfo`.
 *
 * @returns the arg.value corresponding to the given `paramInfo`
 */
export function extractArgValue<T extends RCLIArgType>({
    paramInfo,
    argInfos,
    throwIfNotFound,
}: {
    paramInfo: RCLIParamInfo,
    argInfos: RCLIArgInfo<RCLIArgType>[],
    throwIfNotFound?: boolean,
}): T | T[] | undefined {
    const lc = `[${extractArgValue.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: d376123d1e383f6323ef1fc6bb68f123)`); }

        const filteredArgInfos = argInfos.filter(x => x.name === paramInfo.name);

        if (logalot) { console.log(`${lc} filteredArgInfos: ${pretty(filteredArgInfos)} (I: a15831a9bf2930435960263c79d34323)`); }
        if (filteredArgInfos.length === 0) {
            if (throwIfNotFound) {
                throw new Error(`param (name: ${paramInfo.name}) not found among args. (E: a74e41ca7de883f26f216a8d15ab7a23)`);
            } else {
                return undefined;
            }
        }

        if (paramInfo.allowMultiple) {
            // allow multiple args, so return type is T[]
            if (paramInfo.isFlag) { throw new Error(`(UNEXPECTED) param (name: ${paramInfo.name}) is defined as allowMultiple and isFlag, which doesn't make sense. (E: 2854512470b2dde4b9a82fe225d22623)`); }
            if (paramInfo.argTypeName === 'boolean') { throw new Error(`(UNEXPECTED) param (name: ${paramInfo.name}) is defined as allowMultiple and its type name is boolean, which doesn't make sense. (E: 259d77da25374726af4895eb19bb3041)`); }

            if (filteredArgInfos.some(arg => arg.value !== 0 && !arg.value)) {
                throw new Error(`param (name: ${paramInfo.name}) value is not 0 but is falsy. (E: e5af23465f6920a2ff6be7b7d49ef123)`);
            }
            return filteredArgInfos.map(arg => arg.value as T);

        } else {
            // allow only single arg, so return type is T
            if (filteredArgInfos.length > 1) { throw new Error(`param (name: ${paramInfo.name}) had multiple args but param.allowMultiple is falsy. (E: 0d01157e773bd34f962f8713e7719c23)`); }

            const argInfo = filteredArgInfos[0] as RCLIArgInfo<T>;

            // if the flag is set but no `="true"` or `="false"` provided, then
            // we set the value to true
            if (paramInfo.isFlag && argInfo.value === undefined) {
                if (paramInfo.argTypeName !== 'boolean') {
                    throw new Error(`(UNEXPECTED) paramInfo.isFlag is true but argTypeName !== 'boolean' (E: 79a86d0c6ef4c7740aa84211ebadbb23)`);
                }
                argInfo.value = true as T;
            }

            if (logalot) { console.log(`argInfo.value: ${argInfo.value}`) }

            return argInfo.value;
        }
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

// #endregion extractArg functions

// export async function promptForSecret({
//     confirm,
// }: {
//     confirm: boolean,
// }): Promise<string> {
//     const lc = `[${promptForSecret.name}]`;
//     try {
//         console.warn(`WARNING: THIS PASSWORD INPUT IS NOT IMPLEMENTED CORRECTLY WITH REGARDS TO PRIVACY`);
//         const rl = readline.createInterface({
//             input: stdin,
//             output: stdout
//         });
//         let secret: string | undefined = undefined;
//         try {
//             do {
//                 const secret1 =
//                     await rl.question(`enter your secret key for the encryption:\n`);
//                 if (!secret1) {
//                     `no secret provided. please try again.`;
//                     continue;
//                 }
//                 if (confirm) {
//                     const secret2 = await rl.question(`confirm:\n`);
//                     if (secret2 === secret1) {
//                         secret = secret1;
//                     } else {
//                         console.log(`secrets do not match. please try again.`);
//                     }
//                 } else {
//                     secret = secret1;
//                     continue;
//                 }
//             } while (!secret);
//             return secret;
//         } catch (error) {
//             throw error;
//         } finally {
//             rl.close();
//         }
//     } catch (error) {
//         console.error(`${lc} ${error.message}`);
//         throw error;
//     }
// }


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
    indexingMode,
    blockMode,
    hashAlgorithm,
    saltStrategy,
    initialRecursions,
}: {
    secret: string,
    salt: string | undefined,
    strength: GenericEncryptionStrengthSetting,
    indexingMode: AlphabetIndexingMode | undefined,
    blockMode: BlockModeOptions | undefined,
    hashAlgorithm: HashAlgorithm | undefined,
    saltStrategy: SaltStrategy | undefined,
    initialRecursions: number | undefined,
}): Promise<BaseArgs> {
    const lc = `[${getBaseArgsSet.name}]`;
    if (!salt) {
        console.warn(`${lc} generating publicly visible random salt (W: babb0c7eaeef4e33ab8a6e3897624940)`);
        salt = await getUUID();
    }
    if (strength === 'weaker') {
        const args: BaseArgs = {
            secret,
            initialRecursions: initialRecursions ?? 1000,
            salt,
            saltStrategy: saltStrategy ?? 'initialAppend',
            hashAlgorithm: hashAlgorithm ?? 'SHA-256',
            indexingMode: indexingMode ?? 'indexOf',
            recursionsPerHash: 2,
            blockMode,
        }
        return args;
    } else if (strength === 'stronger') {
        blockMode ??= {
            maxBlockSize: 1000,
            // every pass is c. 100 in length, so every 10 passes is 1000 characters per character,
            // really selection of this depends on the length of data, but
            // we'll assume it's relatively small data
            numOfPasses: 100,
        };
        const args: BaseArgs = {
            secret,
            initialRecursions: initialRecursions ?? 30_000,
            salt,
            saltStrategy: saltStrategy ?? 'prependPerHash',
            hashAlgorithm: hashAlgorithm ?? 'SHA-512',
            indexingMode: indexingMode ?? 'lastIndexOf',
            recursionsPerHash: 10,
            blockMode,
        }
        return args;
    } else {
        throw new Error(`unknown strength (${strength}) (E: 8eb1c2c865bd0514b8efd2149fb26523)`);
    }
}

/**
 * gets the paramInfo corresponding to the given argIdentifier
 * @returns paramInfo from given `paramInfos`
 */
export function getParamInfo({ argIdentifier, paramInfos }: {
    /**
     * arg identifier is either a name or a synonym. atow only a name.
     */
    argIdentifier: string,
    /**
     * All possible param infos that the given arg identifier could be.
     *
     * I have this separate as I plan to pull this out into a separate lib
     * (maybe helper-gib).
     */
    paramInfos: RCLIParamInfo[]
}): RCLIParamInfo {
    const lc = `[${getParamInfo.name}]`;
    try {
        const filteredParamInfos = paramInfos.filter(p => p.name === argIdentifier);
        if (filteredParamInfos.length === 1) {
            return filteredParamInfos[0];
        } else if (filteredParamInfos.length > 1) {
            throw new Error(`(UNEXPECTED) multiple param infos found with argIdentifier (${argIdentifier}) (E: d599a6647c5ead6d9fbac4e4c96e6d23)`);
        } else {
            throw new Error(`(UNEXPECTED) param info not found for argIdentifier (${argIdentifier}) (E: 47e704068f2eb5a0551cf45d0e72c823)`);
        }
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    }
}
