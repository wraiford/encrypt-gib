import { RCLIParamInfo } from "@ibgib/helper-gib/dist/rcli/rcli-types.mjs";
import { COMMON_PARAM_INFOS } from "@ibgib/helper-gib/dist/rcli/rcli-constants.mjs";

export const ENCRYPTED_OUTPUT_FILE_EXT = 'encrypt-gib';

export const PARAM_INFO_ENCRYPT: RCLIParamInfo = {
    name: 'encrypt',
    isFlag: true,
    argTypeName: 'boolean',
    description: 'flag to indicate a encrypt command'
};
export const PARAM_INFO_DECRYPT: RCLIParamInfo = {
    name: 'decrypt',
    isFlag: true,
    argTypeName: 'boolean',
    description: 'flag to indicate a decrypt command'
};
export const PARAM_INFO_STRENGTH: RCLIParamInfo = {
    name: 'strength',
    argTypeName: 'string',
    description: 'convenience param. broad strength configuration to determine some default encrypt/decrypt parameters. kind of like an alias of a param set, useful if you don\'t want to specify all of your individual parameters. i dunno, all of this is use at your own risk.'
};
export const PARAM_INFO_SALT: RCLIParamInfo = {
    name: 'salt',
    argTypeName: 'string',
    description: 'salt to use with each call to hash. used in conjunction with saltStrategy.'
};
export const PARAM_INFO_INDEXING_MODE: RCLIParamInfo = {
    name: 'indexing-mode',
    argTypeName: 'string',
    description: 'mode used when indexing into a jit alphabet per round. can be "indexOf" or "lastIndexOf". when trying to mitigate against brute forcing, "lastIndexOf" should be used so that the entire hash chain is required in order to index into (i think).'
};
export const PARAM_INFO_BLOCKMODE_FLAG: RCLIParamInfo = {
    name: 'block-mode',
    argTypeName: 'boolean',
    isFlag: true,
    description: 'if true, will execute encrypt/decrypt in a block mode to help mitigate brute force short-circuit attacks.'
};
export const PARAM_INFO_BLOCKMODE_BLOCK_SIZE: RCLIParamInfo = {
    name: 'block-size',
    argTypeName: 'integer',
    description: 'the number of plaintext chars to encipher as a group before proceeding to the next block/group. this can increase processing time and in general act as a memory-hard barrier or significant processing increase.'
};
export const PARAM_INFO_BLOCKMODE_NUM_OF_PASSES: RCLIParamInfo = {
    name: 'num-of-passes',
    argTypeName: 'integer',
    description: 'number of passes per block of plaintext. so if you process data in blocks of 5 and you set this to 10, you will encipher each plaintext char a total of 10 times, but each encipherment happens after the entire previous iteration completes.'
};
export const PARAM_INFO_HASH_ALGORITHM: RCLIParamInfo = {
    name: 'hash-algorithm',
    argTypeName: 'string',
    description: 'specifies the type of hash function to use per round'
};
export const PARAM_INFO_SALT_STRATEGY: RCLIParamInfo = {
    name: 'salt-strategy',
    argTypeName: 'string',
    description: 'the type of salt combining at the initial keystretch phase, as well as per recursive hash inside each round.'
};
export const PARAM_INFO_INITIAL_RECURSIONS: RCLIParamInfo = {
    name: 'initial-recursions',
    argTypeName: 'integer',
    description: 'the initial number of recursive hash functions to execute at the beginning of the encryption (before any round functions are applied on plaintext). this is essentially the key stretching phase.'
};
export const PARAM_INFO_RECURSIONS_PER_HASH: RCLIParamInfo = {
    name: 'recursions-per-hash',
    argTypeName: 'integer',
    description: 'the number of recursive hash functions to execute per round/plaintext character.'
};

/**
 * Array of all parameters this library's RLI supports.
 */
export const PARAM_INFOS: RCLIParamInfo[] = [
    ...COMMON_PARAM_INFOS,
    PARAM_INFO_ENCRYPT,
    PARAM_INFO_DECRYPT,
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
