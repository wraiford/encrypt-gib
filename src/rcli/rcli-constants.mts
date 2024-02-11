import { RCLIParamInfo } from "@ibgib/helper-gib/dist/rcli/rcli-types.mjs";
import { COMMON_PARAM_INFOS } from "@ibgib/helper-gib/dist/rcli/rcli-constants.mjs";

export const ENCRYPTED_OUTPUT_FILE_EXT = 'encrypt-gib';

// export const PARAM_INFO_HELP: RCLIParamInfo = {
//     name: 'help',
//     isFlag: true,
//     argTypeName: 'boolean',
// };
// export const PARAM_INFO_DATA_PATH: RCLIParamInfo = {
//     name: 'data-path',
//     argTypeName: 'string',
// };
// export const PARAM_INFO_OUTPUT_PATH: RCLIParamInfo = {
//     name: 'output-path',
//     argTypeName: 'string',
// };
// export const PARAM_INFO_DATA_STRING: RCLIParamInfo = {
//     name: 'data-string',
//     argTypeName: 'string',
// };
export const PARAM_INFO_ENCRYPT: RCLIParamInfo = {
    name: 'encrypt',
    isFlag: true,
    argTypeName: 'boolean',
};
export const PARAM_INFO_DECRYPT: RCLIParamInfo = {
    name: 'decrypt',
    isFlag: true,
    argTypeName: 'boolean',
};
export const PARAM_INFO_STRENGTH: RCLIParamInfo = {
    name: 'strength',
    argTypeName: 'string',
};
export const PARAM_INFO_SALT: RCLIParamInfo = {
    name: 'salt',
    argTypeName: 'string',
};
export const PARAM_INFO_INDEXING_MODE: RCLIParamInfo = {
    name: 'indexing-mode',
    argTypeName: 'string',
};
export const PARAM_INFO_BLOCKMODE_FLAG: RCLIParamInfo = {
    name: 'blockMode',
    // name: 'multipass',
    argTypeName: 'boolean',
    isFlag: true,
};
export const PARAM_INFO_BLOCKMODE_BLOCK_SIZE: RCLIParamInfo = {
    // name: 'section-length',
    name: 'block-size',
    argTypeName: 'integer',
};
export const PARAM_INFO_BLOCKMODE_NUM_OF_PASSES: RCLIParamInfo = {
    name: 'num-of-passes',
    argTypeName: 'integer',
};
export const PARAM_INFO_HASH_ALGORITHM: RCLIParamInfo = {
    name: 'hash-algorithm',
    argTypeName: 'string',
};
export const PARAM_INFO_SALT_STRATEGY: RCLIParamInfo = {
    name: 'salt-strategy',
    argTypeName: 'string',
};
export const PARAM_INFO_INITIAL_RECURSIONS: RCLIParamInfo = {
    name: 'initial-recursions',
    argTypeName: 'integer',
};

/**
 * Array of all parameters this library's RLI supports.
 */
export const PARAM_INFOS: RCLIParamInfo[] = [
    ...COMMON_PARAM_INFOS,
    // PARAM_INFO_HELP,
    PARAM_INFO_ENCRYPT,
    PARAM_INFO_DECRYPT,
    // PARAM_INFO_DATA_PATH,
    // PARAM_INFO_OUTPUT_PATH,
    // PARAM_INFO_DATA_STRING,
    PARAM_INFO_STRENGTH,
    PARAM_INFO_SALT,
    PARAM_INFO_INDEXING_MODE,
    PARAM_INFO_BLOCKMODE_FLAG,
    PARAM_INFO_BLOCKMODE_BLOCK_SIZE,
    PARAM_INFO_BLOCKMODE_NUM_OF_PASSES,
    PARAM_INFO_HASH_ALGORITHM,
    PARAM_INFO_SALT_STRATEGY,
    PARAM_INFO_INITIAL_RECURSIONS,
];
