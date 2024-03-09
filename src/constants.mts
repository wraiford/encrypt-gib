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
 * Default value for the maximum size of a block, when using block mode (if the
 * total plaintext data is smaller than this, then the effective block size is
 * that data's length).
 *
 * This is essentially how many groups of hex-encoded plaintext characters are
 * we going to iterate on at one time with multiple passes. So if you have a
 * block size of 1000, then the block mode encryption will have to keep in
 * memory (or store/retrieve dynamically if an attacker rewrites this library's
 * internals) at least 1000 hashes for the entire block before being able to
 * compute the second pass's hash of the first character. So for 2 passes and a
 * hashLength (digestLength) of 64 bytes, this would be roughly 1000 *
 * hashLength bytes * (numOfPasses - 1)~~> 64 kB of memory. (though really I
 * think this is 128 kB because current implementation just treats the digest as
 * a string)
 *
 * Used in block mode.
 */
export var DEFAULT_MAX_BLOCK_SIZE: number = 5_000_000;
/**
 * Default value for the number of passes when using block mode.
 *
 * Used in block mode
 */
export var DEFAULT_NUM_OF_PASSES: number = 4;

export var DEFAULT_ENCRYPTED_DATA_DELIMITER: string = ',';
