import { RLIParamInfo } from "./rli-types.mjs";

export const ENCRYPTED_OUTPUT_FILE_EXT = 'encrypt-gib';

export const PARAM_INFO_HELP: RLIParamInfo = {
    name: 'help',
    isFlag: true,
    argTypeName: 'boolean',
};
export const PARAM_INFO_ENCRYPT: RLIParamInfo = {
    name: 'encrypt',
    isFlag: true,
    argTypeName: 'boolean',
};
export const PARAM_INFO_DECRYPT: RLIParamInfo = {
    name: 'decrypt',
    isFlag: true,
    argTypeName: 'boolean',
};
export const PARAM_INFO_DATA_PATH: RLIParamInfo = {
    name: 'data-path',
    argTypeName: 'string',
};
export const PARAM_INFO_OUTPUT_PATH: RLIParamInfo = {
    name: 'output-path',
    argTypeName: 'string',
};
export const PARAM_INFO_DATA_STRING: RLIParamInfo = {
    name: 'data-string',
    argTypeName: 'string',
};
export const PARAM_INFO_STRENGTH: RLIParamInfo = {
    name: 'strength',
    argTypeName: 'string',
};
export const PARAM_INFO_SALT: RLIParamInfo = {
    name: 'salt',
    argTypeName: 'string',
};
export const PARAM_INFO_INDEXING_MODE: RLIParamInfo = {
    name: 'indexing-mode',
    argTypeName: 'string',
};
export const PARAM_INFO_MULTIPASS_FLAG: RLIParamInfo = {
    name: 'multipass',
    argTypeName: 'boolean',
    isFlag: true,
};
export const PARAM_INFO_MULTIPASS_SECTION_LENGTH: RLIParamInfo = {
    name: 'section-length',
    argTypeName: 'integer',
};
export const PARAM_INFO_MULTIPASS_NUM_OF_PASSES: RLIParamInfo = {
    name: 'num-of-passes',
    argTypeName: 'integer',
};
export const PARAM_INFO_HASH_ALGORITHM: RLIParamInfo = {
    name: 'hash-algorithm',
    argTypeName: 'string',
};
export const PARAM_INFO_SALT_STRATEGY: RLIParamInfo = {
    name: 'salt-strategy',
    argTypeName: 'string',
};
export const PARAM_INFO_INITIAL_RECURSIONS: RLIParamInfo = {
    name: 'initial-recursions',
    argTypeName: 'integer',
};

/**
 * Array of all parameters this library's RLI supports.
 */
export const PARAM_INFOS: RLIParamInfo[] = [
    PARAM_INFO_HELP,
    PARAM_INFO_ENCRYPT,
    PARAM_INFO_DECRYPT,
    PARAM_INFO_DATA_PATH,
    PARAM_INFO_OUTPUT_PATH,
    PARAM_INFO_DATA_STRING,
    PARAM_INFO_STRENGTH,
    PARAM_INFO_SALT,
    PARAM_INFO_INDEXING_MODE,
    PARAM_INFO_MULTIPASS_FLAG,
    PARAM_INFO_MULTIPASS_SECTION_LENGTH,
    PARAM_INFO_MULTIPASS_NUM_OF_PASSES,
    PARAM_INFO_HASH_ALGORITHM,
    PARAM_INFO_SALT_STRATEGY,
    PARAM_INFO_INITIAL_RECURSIONS,
];
