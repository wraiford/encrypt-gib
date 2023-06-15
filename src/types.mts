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
export const SaltStrategy = {
    /**
     * EACH time we hash anything in a round function or initial key-stretching,
     * we will prepend the salt via string concatenation with the secret, if
     * initial (salt + secret), else with the previous hash (salt + prev).
     */
    prependPerHash: 'prependPerHash' as SaltStrategy,
    /**
     * EACH time we hash anything in a round function or initial key-stretching,
     * we will append the salt via string concatenation with the secret, if
     * initial (secret + salt), else with the previous hash (prev + salt).
     */
    appendPerHash: 'appendPerHash' as SaltStrategy,
    /**
     * We will only prepend the salt to the secret (salt + secret) via string
     * concatenation ONLY in the initial key-stretching recurions phase.
     */
    initialPrepend: 'initialPrepend' as SaltStrategy,
    /**
     * We will only append the salt to the secret (secret + salt) via string
     * concatenation ONLY in the initial key-stretching recurions phase.
     */
    initialAppend: 'initialAppend' as SaltStrategy,
} as const satisfies { [key: string]: SaltStrategy };
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
export const HASH_ALGORITHMS: HashAlgorithm[] = Object.values(HashAlgorithm);

export type AlphabetIndexingMode = 'indexOf' | 'lastIndexOf';
export const AlphabetIndexingMode = {
    indexOf: 'indexOf',
    lastIndexOf: 'lastIndexOf',
} satisfies { [key: string]: AlphabetIndexingMode };
export const ALPHABET_INDEXING_MODES: AlphabetIndexingMode[] = Object.values(AlphabetIndexingMode);

/**
 * The block-mode algorithm works as follows:
 *
 * ## encrypting
 *
 * * plaintext characters - p0, p1, .., pi
 * * JIT alphabet hashes - [a0.0, a0.1, a0.2, .., a0.j], [a1.0, a1.1, a1.2, .., a1.j], .., [ai.0, ai.1, ai.2, .., ai.j]
 *   * i = plaintext index
 *   * j = alphabet expansion index
 * * passes - PASS1, PASS2, .., PASSn
 *
 * 1. First we iterate through the plaintext data in multipass blocks, the
 * size of which is parameterized by `maxBlockSize`. If this is larger
 * than data, then the entire plaintext will be used.
 *
 * 2. Then we create the initial alphabets for the entire section, determined by
 * our pass section size and the number of passes.
 *
 * 3. We then extend any individual alphabets that do not contain an instance of
 * the plaintext character yet. We are extending only those alphabets in need of
 * extending, as opposed to the previous step where we extended all alphabets in
 * the pass section.
 *
 * 4. We get the index of each plaintext character into its corresponding
 * alphabet and store each index in an array for the entire multipass block.
 * We then concat this new section with any previous sections encrypted,
 * building out our entire result `encryptedData` array section by section.
 *
 * 5. Lastly, we return the array as a string, joining each index with the
 * parameterized delimiter (comma by default).
 *
 * ## decrypting
 *
 * The decryption process is very similar.
 *
 * 1. First we iterate through the ciphertext data in multipass blocks, the
 * size of which must be the same as the encryption process (all parameters
 * should be the same encrypting and decrypting. these are automatically stored
 * in encryption output file).
 *
 * 2. Next we create our alphabets for the entire section. The first phase of
 * this is to build out the minimum sized alphabets per parameters
 * (`numOfPasses`).
 *
 * 3. Next we iterate through the encryped indexes for the section. While the
 * index is larger than the existing alphabet, the alphabet is JIT extended by
 * the hash round function. Once the alphabet is large enough (i.e. the
 * encrypted index can index into it), the the encrypted index is used in the
 * alphabet and the plaintext hex character is stored in a result array for the
 * section.
 *
 * 4. Once the entire section is decrypted to hex, the section's plaintext array
 * is added to the previously decrypted sections' plaintext results.
 *
 * 5. Once all sections are decrypted to hex, the plaintext array is converted to a
 * hex string and then decoded to the original plaintext.
 */
export interface BlockModeOptions {
    /**
     * Maximum number of **hex-encoded** plaintext characters per section when
     * making multiple passes. Each pass extends the JIT alphabet for each
     * character in that pass by the length of the hash digest being used (since
     * the hashes are what the alphabets are made of).
     *
     * * If this is greater than the hex-encoded `dataToEncrypt` length, then
     *   each pass section will be the length of data (it's goin to do the whole
     *   plaintext in one section).
     * * Barring internal JS voodoo, each pass should require additional memory
     *   roughly linearly proportional to
     *   * `dataToEncrypt`/`maxBlockSize` length (whichever is smaller)
     *   * `numOfPasses` to make
     *   * length of the hash used in creating the JIT alphabets (`hashAlgorithm`)
     * * The larger `maxBlockSize` & `numOfPasses` is, the more a brute
     *   force attack has to calculate - and the more memory it is going to take
     *   - before determining if a secret guess is correct.
     */
    maxBlockSize: number;
    /**
     * @deprecated
     *
     * use {@link maxBlockSize}
     */
    maxPassSectionLength?: number;
    /**
     * Number of "passes" to make over the pass section. Each pass will extend
     * the JIT alphabet for each character in the pass section by the length of
     * the hash digest string used in `hashAlgorithm`.
     *
     * This should be especially effective in mitigating against brute force
     * cracking when used in tandem with an `indexingMode` of `lastIndexOf`.
     * This is because at least `(numOfPasses - 1) * maxBlockSize`
     * number of hash rounds must be calculated before the very first plaintext
     * character can be deciphered. This is even more expensive if
     * `recursionsPerHash` is larger.
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
     * So if the JIT hex alphabet is abc123abc456 and our character is b:
     *
     * abc123abc456
     *  ^     ^
     *  1
     * * `'indexOf'` -> 1
     * * `'lastIndexOf'` -> 7
     *
     * with immediately expanding JIT alphabets, this shouldn't make much of a
     * difference.  But when mitigating brute force short-circuit attacks, where
     * the brute forcer only decrypts the first couple of characters of data, we
     * may combine `'lastIndexOf'` with a "multipass" expanding alphabet to
     * ensure that a larger portion of the plaintext (up to 100% of the
     * plaintext), is required to be processed before any short-circuiting
     * decryption can occur. @see {@link BlockModeOptions}
     *
     * To help understand this, here is an example. Say we use a multi-pass
     * alphabet that requires a minimum of 3 expansions. We encipher the first
     * character of plaintext we first convert that character to hex. Say this
     * hex is 'a'. Now we create our corresponding alphabet by recursively
     * rounding on the initial `prevHash` (after key stretching with
     * `initialRecursions` has occurred). Say one round produces a hash
     * '123a56ba90' for our one-time JIT alphabet. If this were an immediately
     * expanding JIT alphabet with no minimum expansions and the ciphertext is
     * already present, then additional rounds won't be needed for the attacker
     * - they already have the index and the alphabet that has the plaintext.
     *
     * With `lastIndexOf` + multipass blocks, then the attacker is forced to
     * calculate at least the entire section's hashing because the encrypted
     * index will most likely be at the end of the alphabet.
     *
     * abc123...[200ish hex character]...bac231
     *                                      ^
     * The first `indexOf('2')` would just be 4, and no other alphabet
     * extensions would be required (not a single one in the section).  Whereas
     * the `lastIndexOf('2')` would be a 200+ index. This would require multiple
     * hashes for every previous character in the section, and would thus harder
     * to short-circuit.
     *
     * @default `'indexOf'`
     */
    indexingMode?: AlphabetIndexingMode;
    /**
     * Settings to use if we want to use multiple passes when
     * encrypting/decrypting.
     *
     * This is one way to help mitigate against short-circuit brute force
     * attacks.
     *
     * @see {@link BlockModeOptions}
     */
    blockMode?: BlockModeOptions;
    /**
     * @deprecated
     *
     * Use `blockMode` instead.
     */
    multipass?: BlockModeOptions;
    /**
     * The hash algorithm to use.
     *
     * ATOW, this is either 'SHA-256' or 'SHA-512'.
     *
     * @see {@link HashAlgorithm} for current values.
     */
    hashAlgorithm?: HashAlgorithm;
    /**
     * The amount of recursions from the secret + salt to start actual
     * encryption mapping.
     *
     * The bigger this is, the more time it takes to try guesses for an
     * attacker, depending on how expensive the hash function is. But also the
     * more time it would take on the legitimate user's password attempt.
     */
    initialRecursions: number;
    /**
     * The number of recursive hashes we perform for each round function of
     * hashing (except the initial recursions, see `initialRecursions` param).
     *
     * This includes both when we hash each hex character of our hex-encoded
     * data, as well as each time we JIT extend the alphabet when the plaintext
     * hex character isn't found in the current JIT hash alphabet.
     *
     * So, if the initial hash alphabet is all a's (e.g. "aaa...a", a very
     * contrived hash!), but our hex data is a b, then we will hash the all-a
     * hash {recursionsPerHash} times to expand the alphabet.
     *
     * @example
     * So if we have a data character of 'b', and its immediate hash alphabet is
     * all a's, and we recurse 3 times per hash (ignoring salts for this
     * example), here is some simplified pseudo code to give the gist:
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
     * In actuality, the code will include salt and saltStrategy, and track how
     * many times the alphabet expands to get the correct index.
     *
     * Note that this does not add on each and every recursive hash produced. It
     * only adds on the last hash after recursionsPerHash number of hashes (i.e.
     * the alphabet is JIT extended the length of a single hash digest - the
     * last one).
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
export interface BaseArgs extends BaseBase {
    secret: string;
}

/**
 * Info passed to the `encrypt` function.
 */
export interface EncryptArgs extends BaseArgs {
    /**
     * Plaintext data string
     */
    dataToEncrypt: string;
    /**
     * If true, will decrypt back and confirm that the decryption was
     * successfully performed and the original plaintext is recoverable via the
     * decryption process.
     *
     * Takes more time & resources.
     */
    confirm?: boolean;
}

/**
 * Info passed to the `decrypt` function.
 */
export interface DecryptArgs extends BaseArgs {
    /**
     * String of delimited encrypted indexes.
     */
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
    /**
      String of delimited encrypted indexes.
     */
    encryptedData?: string;
}

/**
 * Result info from `decrypt` function.
 */
export interface DecryptResult extends BaseResult {
    decryptedData?: string;
}
