import { AlphabetIndexingMode, HashAlgorithm, SaltStrategy } from "./index.mjs";

export var DEFAULT_SALT_STRATEGY: SaltStrategy = SaltStrategy.appendPerHash;
// export var DEFAULT_HASH_ALGORITHM: HashAlgorithm = 'SHA-256';
export var DEFAULT_HASH_ALGORITHM: HashAlgorithm = 'SHA-512';
export var DEFAULT_GETUUID_SEEDSIZE: number = 1024;
export var DEFAULT_INITIAL_RECURSIONS: number = 20000;
export var DEFAULT_RECURSIONS_PER_HASH: number = 1;
export var DEFAULT_ALPHABET_INDEXING_MODE: AlphabetIndexingMode = 'indexOf';
export var DEFAULT_ADDITIONAL_PASSES: number = 0;
export var DEFAULT_ADDITIONAL_PASSES_INTERMEDIATE_SECRET_LENGTH: number = 32;
/**
 * used in `generateNewIntermediatePassSecretAddendum`
 * @internal
 */
export var INTERNAL_MAGIC_DEFAULT_ADDITIONAL_PASSES_MIN_LENGTH: number = 10;

export var DEFAULT_ENCRYPTED_DATA_DELIMITER: string = ',';
