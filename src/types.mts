/**
 * There are multiple ways to incorporate the salt into the overall algorithm.
 * See the individual constant properties for details.
 *
 * {@link SaltStrategy} constant
 */
export type SaltStrategy =
    'prependPerHash' | 'appendPerHash' |
    'initialPrepend' | 'initialAppend';
/**
 * enum-like constant for use in tandem with `SaltStrategy` type.
 *
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
} satisfies { [key: string]: SaltStrategy };
/**
 * convenience constant array containing all of `Object.values(SaltStrategy)`
 */
export const SALT_STRATEGIES: SaltStrategy[] = Object.values(SaltStrategy);

/**
 * Hash algorithm type.
 *
 * atow this is only SHA-256 and SHA-512 because both of these are relatively
 * strong and are supported in both node and browser environments. I have found
 * conflicting information on whether or not these are post-quantum secure.
 */
export type HashAlgorithm = 'SHA-256' | 'SHA-512';
/**
 * enum-like constant for use in tandem with `HashAlgorithm` type.
 */
export const HashAlgorithm = {
    'sha_256': 'SHA-256' as HashAlgorithm,
    'sha_512': 'SHA-512' as HashAlgorithm,
} satisfies { [key: string]: HashAlgorithm };

/**
 * THIS PARAMETER SETTING IS PUBLIC AND VIEWABLE IN PLAINTEXT.
 * BUT IT GENERATES ENCRYPTED META-SETTINGS INCLUDED IN OUTPUT CIPHERTEXT.
 *
 * When brute force decrypting ciphertext encrypted with encrypt-gib's
 * algorithm, it is possible to just check the first n number of characters
 * against expected output reasonableness.
 *
 * For example, even if the data is 1 GB in size but you know the data is a JSON
 * object, you only would have to check the first 100 bytes (or less!) to see if
 * you're getting a JSON object decrypted. If you only get a bunch of random
 * Unicode characters, then the password is most likely wrong and you can move
 * on to the next password guess.
 *
 * These parameters are specifically to mitigate against this type of brute
 * force attack, but may not be necessary in performance vs security tradeoff.
 */
export interface BruteForceShortCircuitMitigationInfo {

    // /**
    //  *
    //  */
    // padding?: PaddingMitigationInfo;
}

/**
 * THIS PARAMETER SETTING IS PUBLIC AND VIEWABLE IN PLAINTEXT.
 * BUT IT GENERATES ENCRYPTED META-SETTINGS INCLUDED IN OUTPUT CIPHERTEXT.
 *
 * Settings to add auto-generated fake "filler" data to the
 * end result ciphertext. This requires
 */
// export interface PaddingMitigationInfo {
//     minPrePadLength?: number;
//     maxPrePadLength?: number;
//     minPostPadLength?: number;
//     maxPostPadLength?: number;
// }

export type AlphabetIndexingMode = 'indexOf' | 'lastIndexOf';
export const AlphabetIndexingMode = {
    indexOf: 'indexOf',
    lastIndexOf: 'lastIndexOf',
} satisfies { [key: string]: AlphabetIndexingMode };
export const ALPHABET_INDEXING_MODES: AlphabetIndexingMode[] = Object.values(AlphabetIndexingMode);

/**
 * The multipass works as follows:
 *
 * ## encrypting
 *
 * * plaintext characters - p0, p1, .., pi
 * * jit alphabet hashes - [a0.0, a0.1, a0.2, .., a0.j], [a1.0, a1.1, a1.2, .., a1.j], .., [ai.0, ai.1, ai.2, .., ai.j]
 *   * i = plaintext index
 *   * j = alphabet expansion index
 * * passes - PASS1, PASS2, .., PASSn
 *
 * 1. First we iterate through the plaintext data in "pass sections", the size
 * of which is parameterized by `maxPassSectionLength`. If this is larger than
 * data, then the entire plaintext will be used.
 *
 * 2. Then we create the initial alphabets for the entire section, determined by
 * our pass section size and the number of passes.
 *
 * 3. We then extend any individual alphabets that do not contain an instance of
 * the plaintext character yet. We are extending only those alphabets in need of
 * extending, as opposed to the previous step where we extended all alphabets in
 * the pass section.
 *
 * 4. Finally we get the indexes of each plaintext character in their
 * corresponding alphabets and store these into an array and then appending this
 * array to our global encryption index result. Of course we return the array as
 * a string, joined by our delimiter.
 *
 * ## decrypting
 */
export interface MultipassOptions {
    /**
     * Maximum number of **hex-encoded** plaintext characters per section when
     * making multiple passes. Each pass extends the jit alphabet per character
     * in that pass.
     *
     * * If this is greater than the hex-encoded dataToEncrypt length, then each
     *   pass section will be the length of data (it's goin to do the whole thing).
     * * Each pass will require additional memory roughly linearly proportional to
     *   * dataToEncrypt length
     *   * numOfPasses to make
     *   * length of the hash used in creating the jit alphabets (`hashAlgorithm`)
     * * The higher the pass length, the more a brute force attack has to
     *   calculate before determining if a secret guess is correct.
     */
    maxPassSectionLength: number;
    /**
     * Number of "passes" to make over the pass section. Each pass will
     * extend the jit alphabet for each character in the pass section by
     * the length of the hash digest string used in `hashAlgorithm`.
     */
    numOfPasses: number;
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
     * when iterating characters, this determines whether we are using `'indexOf'` or
     * `'lastIndexOf'` on the alphabet string.
     *
     * So if the jit hex alphabet is abc123abc456 and our character is b:
     *
     * abc123abc456
     *  ^     ^
     *  1
     * * `'indexOf'` -> 1
     * * `'lastIndexOf'` -> 7
     *
     * with immediately expanding jit alphabets, this shouldn't make much of a
     * difference.  But when mitigating brute force short-circuit attacks, where
     * the brute forcer only decrypts the first couple of characters of data, we
     * may combine `'lastIndexOf'` with a "multi-pass" expanding alphabet to
     * ensure that a larger portion of the plaintext (up to 100% of the plaintext),
     * is required to be processed before any short-circuiting decryption can occur.
     *
     * To help understand this, here is an example. Say we use a multi-pass
     * alphabet that requires a minimum of 3 expansions. We encipher the first character
     * of plaintext we first convert that character to hex. Say this hex is 'a'. Now we
     * create our corresponding alphabet by recursively rounding on the initial `prevHash`
     * (after key stretching with `initialRecursions` has occurred). Say one round produces a hash
     * '123a56ba90' for our 1-time jit alphabet. If this were an immediately expanding jit alphabet
     * with no minimum expansions
     *
     * @default `'indexOf'`
     */
    indexingMode?: AlphabetIndexingMode;
    /**
     * Settings to use if we want to use multiple passes when encrypting/decrypting.
     *
     * This is one way to help mitigate against short-circuit brute force attacks.
     *
     * @see {@link MultipassOptions}
     */
    multipass?: MultipassOptions;
    /**
     * Minimum number of expansions BEYOND that required (once a match in the alphabet for
     * the hex character to be encoded is found).
     *
     * @default 0
     *
     * @example
     * suppose this value is 2 and the plaintext hex character to be encoded is
     * 'a', then the total alphabet will be as follows, given the alphabet
     * expansions (supposing that the hashes/expansions are of length 6):
     *
     *
     * case #1
     * abc123
     * ^
     * plaintext character found in very first jit alphabet.
     * we add two superfluous expansions beyond this, 'def456' and 'ghi789'.
     * abc123 + def456 + ghi789
     *          ^^^^^^   ^^^^^^ (2 additional expansions)
     * abc123def456ghi789
     * ^
     * now, with the superfluous expansions, our alphabet (length of 3 * 6 = 18)
     * still only contains one 'a' so `indexOf` and `lastIndexOf` are equal:
     * indexOf('a') === 0
     * lastIndexOf('a') === 0
     *
     *
     * case #2
     * def456 + ghi789 + abc123
     *                   ^
     * plaintext character 'a' not found until initial alphabet 'def456' expanded twice.
     * def456ghi789abc123
     *             ^
     * indexOf('a') === 12
     * we add two superfluous expansions beyond this, '012bca' and '345fed'.
     * def456 + ghi789 + abc123 + 012bca + 345fed
     *                            ^^^^^^   ^^^^^^
     * def456ghi789abc123012bca345fed
     *             ^          ^
     * now, with the superfluous expansions, our alphabet (length of 5 * 6 = 30)
     * contains two instances of the character, so `indexOf` and `lastIndexOf`
     * differ:
     * indexOf('a') === 12
     * lastIndexOf('a') === 23
     */
    minSuperfluousAlphabetExpansions?: number;
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

/**
 * Args-specific info, in contrast to result-specific info
 *
 * @see {@link BaseResult}
 */
interface BaseArgs extends BaseBase {
    secret: string;
}

/**
 * Info passed to the `encrypt` function.
 */
export interface EncryptArgs extends BaseArgs {
    dataToEncrypt: string;
    /**
     * If true, will decrypt back and check hashes of data.
     *
     * Takes more time & resources.
     */
    confirm?: boolean;
}

/**
 * Info passed to the `decrypt` function.
 */
export interface DecryptArgs extends BaseArgs {
    encryptedData: string;
}

/**
 * Result-specific info, in contrast to args-specific info
 *
 * @see {@link BaseArgs}
 */
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

/**
 * Result info from `encrypt` function.
 */
export interface EncryptResult extends BaseResult {
    encryptedData?: string;
    lastAlphabet?: string;
}

/**
 * Result info from `decrypt` function.
 */
export interface DecryptResult extends BaseResult {
    decryptedData?: string;
}
