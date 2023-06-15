import { AlphabetIndexingMode, HashAlgorithm, SaltStrategy } from "./index.mjs";

export const ENCRYPT_LOG_A_LOT = false;

export var DEFAULT_SALT_STRATEGY: SaltStrategy = SaltStrategy.appendPerHash;
// export var DEFAULT_HASH_ALGORITHM: HashAlgorithm = 'SHA-256';
export var DEFAULT_HASH_ALGORITHM: HashAlgorithm = 'SHA-512';
export var DEFAULT_GETUUID_SEEDSIZE: number = 1024;
export var DEFAULT_INITIAL_RECURSIONS: number = 20000;
export var DEFAULT_RECURSIONS_PER_HASH: number = 1;
/**
 * This must be indexOf for backwards compatibility.
 */
export var DEFAULT_ALPHABET_INDEXING_MODE_LEGACY: AlphabetIndexingMode = 'indexOf';
/**
 * In multipass, which is being developed to help mitigate against short-circuit
 * brute force attacks, I believe it's safer to use `lastIndexOf` in order to
 * leverage the alphabet extensions in other options. This may turn out to be
 * unnecessary.
 */
export var DEFAULT_ALPHABET_INDEXING_MODE_BLOCKMODE: AlphabetIndexingMode = 'lastIndexOf';
/**
 * Maximum size of a block, when using block mode.
 *
 * This is similar to a block size, but the final data section may not be the same size.
 *
 * Used in block mode.
 */
export var DEFAULT_MAX_BLOCK_SIZE: number = 500;
/**
 * Default value for the number of passes when using block mode.
 *
 * Used in block mode
 */
export var DEFAULT_NUM_OF_PASSES: number = 4;

export var DEFAULT_ENCRYPTED_DATA_DELIMITER: string = ',';
