/**
 * {@link SaltStrategy} constant
 */
export type SaltStrategy =
    'prependPerHash' | 'appendPerHash' |
    'initialPrepend' | 'initialAppend';

/**
 * There are multiple ways to incorporate the salt into the overall algorithm.
 * See the individual constant properties for details.
 */
export const SaltStrategy: { [key: string]: SaltStrategy } = {
    /**
     * Each time we hash whatever, we will prepend the salt
     * via string concatenation with the secret, if initial (salt + secret),
     * else with the previous hash (salt + prev).
     */
    prependPerHash: 'prependPerHash' as SaltStrategy,
    /**
     * Each time we hash whatever, we will append the salt
     * via string concatenation with the secret, if initial (secret + salt),
     * else with the previous hash (prev + salt).
     */
    appendPerHash: 'appendPerHash' as SaltStrategy,
    /**
     * We will only prepend the salt to the secret (salt + secret) via
     * string concatenation in the initial recusions hash phase.
     */
    initialPrepend: 'initialPrepend' as SaltStrategy,
    /**
     * We will only append the salt to the secret (secret + salt) via
     * string concatenation in the initial recusions hash phase.
     */
    initialAppend: 'initialAppend' as SaltStrategy,
}

export const SALT_STRATEGIES: SaltStrategy[] = Object.values(SaltStrategy);

export type HashAlgorithm = 'SHA-256' | 'SHA-512';
export const HashAlgorithm: { [key: string]: HashAlgorithm } = {
    'sha_256': 'SHA-256' as HashAlgorithm,
    'sha_512': 'SHA-512' as HashAlgorithm,
}

/**
 * Shared interface among both args and results.
 *
 * ## notes
 *
 * Silly name... naming things hrmm.
 */
interface BaseBase {
    /**
     * The hash algorithm to use. The only one I'm doing atow is 'SHA-256'.
     */
    hashAlgorithm?: HashAlgorithm;
    /**
     * The amount of recursions from the secret + salt to
     * start actual encryption mapping.
     *
     * The bigger this is, the more time it takes to try
     * guesses for an attacker, depending on how expensive
     * the hash function is. But also the more time it would
     * take on the legitimate user's password attempt.
     */
    initialRecursions: number;
    /**
     * The number of recursive hashes we perform for each step of
     * hashing (except the initial recursions, see `initialRecursions` param).
     *
     * This includes both when we hash each hex character of our
     * hex-encoded data, as well as each time we expand the alphabet
     * because the data's hex character wasn't found in the initial
     * hash alphabet.
     *
     * So, if the initial hash alphabet is all a's (e.g. "aaa...a", a very contrived hash!),
     * but our hex data is a b, then we will hash the all-a hash {recursionsPerHash} times
     * to expand the alphabet.
     *
     * @example
     * So if we have a data character of 'b', and its immediate hash alphabet is all a's, and we recurse
     * 3 times per hash (ignoring salts for this example), here is some simplified pseudo code to give
     * the gist:
     *
     * ```javascript
     * dataCharToMap = 'b';
     * alphabet = hash(prevHash) // say it gives us 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
     * needExpandAlphabet = alphabet.includes(dataCharToMap) // false in this case
     * if (needExpandAlphabet) {
     *     hashToAdd = alphabet;
     *     for (i = 0; i < recursionsPerHash; i++) { hashToAdd = hash(hashToAdd); }
     *     alphabet = alphabet + hashToAdd; // say it's now 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab';
     * }
     * index = alphabet.indexOf(dataCharToMap); // 63
     * ```
     *
     * In actuality, the code will include salt and saltStrategy, and track how many times
     * the alphabet expands to get the correct index.
     *
     * Note that this does not add on each recursive hash. It only adds on the last hash
     * after recursionsPerHash number of hashes.
     */
    recursionsPerHash?: number;
    /**
     * text to prepend/append to hashes for increased security.
     *
     * {@link SaltStrategy}
     */
    salt: string;

    /**
     * {@link SaltStrategy}
     */
    saltStrategy?: SaltStrategy;
    /**
     * Encrypted data is just an array of numbers (positive integers).
     * This array is converted to a string by joining with a delimiter.
     * This is that delimiter.
     *
     * @default DEFAULT_ENCRYPTED_DATA_DELIMITER in constants.ts
     */
    encryptedDataDelimiter?: string;
}

interface BaseArgs extends BaseBase {
    secret: string;
}

export interface EncryptArgs extends BaseArgs {
    dataToEncrypt: string;
    /**
     * If true, will decrypt back and check hashes of data.
     *
     * Takes more time & resources.
     */
    confirm?: boolean;
}

export interface DecryptArgs extends BaseArgs {
    encryptedData: string;
}

interface BaseResult extends BaseBase {
    /**
     * If truthy, there were big problems...
     */
    errors?: string[];
    /**
     * If truthy, there were issues...
     */
    warnings?: string[];
}

export interface EncryptResult extends BaseResult {
    encryptedData?: string;
}

export interface DecryptResult extends BaseResult {
    decryptedData?: string;
}

// export interface EncodeArg {
//     /**
//      * This data conceivable contains all sorts of non-hex characters
//      * like symbols (e.g., _.,\/!?:...) and who knows what.
//      */
//     unencodedData: string;
// }

// export interface EncodeResult {
//     /**
//      * This should only contain characters 0-9 and a-z
//      */
//     encodedData: string;
//     errors: string[];
//     warnings: string[];
// }
