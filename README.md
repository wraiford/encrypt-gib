# encrypt-gib - hash-based encryption

Encrypt-gib is a genuinely novel, post quantum encryption algorithm that uses
cryptographic hashes as its only magical primitive, combined with moderately
simple programming.

## tl;dr - up & running

1.  [Clone](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) this repo, [encrypt-gib](https://github.com/wraiford/encrypt-gib/)
2. `cd encrypt-gib`
2. `npm install`
3. `npm run test:quick` OR `npm test` if you want to sit around for hours admiring ibgib's custom respec-gib testing framework.
  * _note: ATOW with testing framework reshuffle to respec-gib, this only runs node tests - not browser tests._

You can find API usage examples in the following respecs:

* [`encrypt-decrypt.light.respec.mts`](./src/encrypt-decrypt.light.respec.mts)
* [`encrypt-decrypt.heavy.respec.mts`](./src/encrypt-decrypt.heavy.respec.mts)
* [`encrypt-decrypt.mitigation.respec.mts`](./src/encrypt-decrypt.mitigation.respec.mts)

## why does this lib exist?

To provide an alternative post quantum candidate to supplement existing
approaches to simplify encryption in order to...

* maximize DRY-ness across distributed codebases
* minimize surface attack area
* minimize esoteric magic
* maximize granularity for Merkle-based DLT functional programming, e.g. smart contracts, API+DIDs, etc.

encrypt-gib is written as a standalone encryption library. But. It's a new
world, one which I've been anticipating for 20+ years now. And these particular
qualities were baked in specifically for use in an open, transparent ecosystem.
This is especially true when used in tandem with the ibgib DLT protocol. The
overall streamlined architecture unifies:

* Version control for mostly text-based source codebases
* Version control for AI model branching and mobility
* Public Key Infrastructure, including Certificate Authorities
* File replication across both fixed and ad hoc configurations
* Consensus across both fixed and ad hoc configurations
* Sovereign DLT-based identity
* Multi/Cross-chain interoperability and collaboration

**Novel innovation to transition from opacity to translucency.**

## how it works

The basic idea is this:

**Use configurable recursive cryptographic hashes for "effectively random", one-time, just-in-time (JIT) alphabets and record indices into these alphabets as our ciphertext.**

So our ciphertext represents indexes into hashes, with configurability on how we
generate those hashes. Currently implemented with SHA-256 or SHA-512, our hash
"alphabets" are in hex, so our data is first hex-encoded. Once we have decided
our hash algorithm, we will key-stretch via recursive hashing of our secret. We
then proceed to encipher (record indexes for) either single characters or larger
sections of characters. For both encryption and decryption, we first build the
relevant alphabet(s) and we either record or dereference the index of the hex
character into that alphabet.

Since we currently support SHA-256 and SHA-512, both are available in NodeJS and
the browser to maximize isomorphic JavaScript. Also as a consequence of using
these hash algorithms, our alphabets are in hex. So, we first encode our
plaintext into hex, and once encoded, we can either stream-encipher hex
character-by-character or encipher larger sections of hex characters. Either
way, we leverage the randomness of hex character distribution in hashes by
creating just-in-time (JIT) one-time alphabets via rounding functions, which
build those alphabets in a plain, low-magic manner, using recursive hashing. We
then publicly record the
**indices** of a characters into their corresponding alphabets. These indexes
are now the ciphertext.

_note: These alphabets are very similar to the keystreams, with recursive hashing used as the round function. But since the combining function is not an XOR, and indeed the stream is not at the bit level but the hex level, the term "alphabet" is more appropriate._

This index-based ciphertext can then be decrypted into the original by
reconstructing the same alphabets based on the same private secret and other
public encryption parameters. We then de-reference the ciphertext indices back
into plaintext hex and finally decode to our original data.

## core implementation

The encryption and decryption code resides in `encrypt-decrypt.ts`.  It exports
two public functions: `encrypt` and `decrypt`.

Here is a walkthrough of the non-multipass stream-only encrypt and decrypt
processes.

### `encrypt`

There are basically four steps in encryption:

1) Encode our data to hex.
2) Perform key-stretch via `initialRecursions` using `secret` and other algorithm parameters, which gives us our starting point for our first alphabet.
3) Iterate through the hex data character by character, creating a one-time alphabet for each individual character based on the previous hash.
4) Record index of plaintext hex character in alphabet, using either `indexOf` or `lastIndexOf` (public parameter), aggregating our ciphertext with each successive index.

_NOTE: The following code is simplified for the example (removed logging, error handling, validation, etc.) Refer to [`encrypt-decrypt.ts`](./src/encrypt-decrypt.mts) for actual code._

```typescript
async function encrypt({
    dataToEncrypt,
    initialRecursions,             // 2
    recursionsPerHash,             // 2
    salt,                          // 'my salt'
    saltStrategy,                  // 'initialPrepend' means salt only on initialRecursions
    secret,                        // 'my p4ssw0rd'
    hashAlgorithm,                 // 'SHA-256'
    encryptedDataDelimiter,        // ','
}: EncryptArgs): Promise<EncryptResult> {

    const hexEncodedData: string = await h.encodeStringToHexString(dataToEncrypt);
    let encryptedData: string = await encryptFromHex({
        hexEncodedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        secret,
        hashAlgorithm,
        encryptedDataDelimiter,
    });

    return { encryptedData ... }
}
```

So for example, say we have a `secret` of `'my p4ssw0rd'` and data of `'foo'`.

First we encode that `'foo'` into hex - say, it comes out to `'42ab'`. Note that since it's
now hex only (0-9, a-f), we're able to fully describe each character of data by an arbitrary length of
concatenated hashes and an index into that JIT "alphabet". But first let's look at the key-stretching code.

Each alphabet is generated via the previous alphabet's last hash, which we will store in `prevHash`.
The very first alphabet will use the last hash generated from the key stretch.

```typescript
let prevHash = await doInitialRecursions({
    secret,                        // 'my p4ssw0rd'
    initialRecursions,             // 2
    salt,                          // 'my salt'
    saltStrategy,                  // 'initialPrepend' means salt only on initialRecursions
    hashAlgorithm,                 // 'SHA-256'
});
// the last hash after initial recursions, say, 'b87ac03382eb47e692e776547f89b72ea475f0a6dc4848039869b1c93a8ab3ba'
```

which has the following implementation...

```typescript
async function doInitialRecursions({
    secret,
    initialRecursions,
    salt,
    saltStrategy,
    hashAlgorithm,
}:... ): Promise<string> {
    let hash: string | undefined;
    for (let i = 0; i < initialRecursions; i++) {
        const preHash = getPreHash({secret, prevHash: hash, salt, saltStrategy});
        hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
    }
    return hash;
}
```
This is where we do our key stretching of our user's secret. It relies on our
rounding function, `getPreHash`:

```typescript
function getPreHash({
    secret,
    prevHash,
    salt,
    saltStrategy,
}: ...): string {
    if (!(prevHash || secret)) { throw new Error(`Either secret or prevHash is required, but both are falsy)`); }
    switch (saltStrategy) {
        case SaltStrategy.prependPerHash:
            return salt + (prevHash || secret)
        case SaltStrategy.appendPerHash:
            return (prevHash || secret) + salt;
        case SaltStrategy.initialPrepend:
            // this is what we'll do in our example
            // salt (prepended!) + secret
            return prevHash ? prevHash : salt + secret; // 'my saltmy p4ssw0rd'
        case SaltStrategy.initialAppend:
            return prevHash ? prevHash : secret + salt;
        default:
            throw new Error(`Unknown saltStrategy: ${saltStrategy}`);
    }
}
```

So we perform a step of key stretching using `secret`, `salt`, `saltStrategy`
and `initialRecursions`.  This stretching ultimately gives us our first
"previous" hash (`prevHash`). It's "previous" in the context of the next
iteration loop.

_note: `initialRecursions` adds a one-time processing cost when encrypting/decrypting._

Now we are able to construct our first alphabet and stream-encipher each
plaintext character in the following steps:

1. iterate through each character,
2. build its uniquely random alphabet, and...
3. record the character's uniquely random index into that alphabet

```typescript
// we'll store our encrypted results here
const encryptedDataIndexes = [];

// iterate through hex characters: '42ab'
for (let i = 0; i < hexEncodedData.length; i++) {

    // character of data that we want to map to an index into the generated alphabet
    const hexCharFromData: string = hexEncodedData[i];

    // build the one-time alphabet for this character, extending the
    // alphabet with additional hashes via recursive round function calls
    // if our alphabet doesn't include the hex character.
    let alphabet: string = "";
    let hash: string;
    while (!alphabet.includes(hexCharFromData)) {
        for (let j = 0; j < recursionsPerHash; j++) {
            const preHash = getPreHash({prevHash, salt, saltStrategy}); // uses prevHash here
            hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
            prevHash = hash;
        }
        alphabet += hash!;
    }

    // we now have the alphabet, so find the index of hex character
    const charIndex = alphabet.indexOf(hexCharFromData); // can also use `lastIndexOf` in parameter

    // hexChar: 4
    // alphabet: 519304f9ad8644869e14935607013348865a0ed45a5b46a8b44f78f2256d3f71
    //                ^
    // charIndex: 5

    // hexChar: 2
    // alphabet: 80a53b7e431e43078fddb90ff286939a24a0617d581546c292924dda2574090c
    //                                    ^
    // charIndex: 25

    // hexChar: a
    // alphabet: 061899d1b28c46d288b569[70chars...]74330d9c16efec504fcfbc3271cee12a45d2
    //                                                                            ^
    // charIndex: 123

    // hexChar: b
    // alphabet: d2ee40490a0c4f47994e3539c8d5109f5ad5549a22134e5399b1d2126bf0562d
    //                                                             ^
    // charIndex: 50

    // store our encrypted results
    encryptedDataIndexes.push(charIndex);
    // [5,25,123,50] (array)
}

const encryptedData = encryptedDataIndexes.join(encryptedDataDelimiter);
return encryptedData;
// '5,25,123,50' (string)
```

We'll talk through some of this code.

Our first `hexCharFromData` has a value of `'4'`. There is a possibility that
the first hash alphabet iteration comprises non-`'4'` hex characters only. This
is why we have the `while (!alphabet.includes(hexCharFromData))`. Strictly
speaking, it's conceivable that we will never generate a hash with that
character (and thus we won't be able to index the `hexCharFromData`). But in
testing, the largest alphabet has been 192 characters (3 alphabet-extending
hashes).

So once we have the `alphabet`, we get the index of `hexCharFromData` into that
alphabet and push that `charIndex` to our encrypted results.

Also note here that with `recursionsPerHash`, we execute these recursions _every
alphabet extension_ for every character. So this adds approximately a linear
processing cost to both encrypting and decrypting
**but only the final hash increases the alphabet size**.

Once we iterate through all of the hex characters, we create the final
`encryptedData` string value by joining the array by our given
`encryptedDataDelimiter`. (Future implementations could instead be smarter about
block sizes of numbers and padding to obviate the need for a delimiter.)

For our simplified example, we'll say this is `'5,25,123,50'`, but in testing
this encryption blows up the size of the data by at least a factor of 5x. Let's
look at each index and what it means.

Recall that our encoded hex is `'42ab'`.

For our first character `'4'`, the first index is `5`, which means that in the
hash alphabet, `5` must have been the first index of `'4'`. It also implies that
the alphabet only required one hash round (but that round will have recursively
hashed `recursionsPerHash` times - in this example's case, twice).

So we'll say the first `alphabet` was:

```
519304f9ad8644869e14935607013348865a0ed45a5b46a8b44f78f2256d3f71
     ^
```

Notice here also that there are `'4'`'s after index `5`, but that this was the
index of the first occurrence.

The same goes for the next encrypted index value of `25` and `'2'` from our hex:

```
80a53b7e431e43078fddb90ff286939a24a0617d581546c292924dda2574090c
                         ^
```

Now the third index of `123` is different. That it is bigger than our hash
length (64) implies the hash alphabet had to be extended, because it did not
have an `'a'` in the first hash:

```
061899d1b28c46d288b569cc1e3d715cdecf0c1431fb4fb9b61672db5451e76784d9e5d4e36b4495bb76e64bcc2e74330d9c16efec504fcfbc3271cee12a45d2
                                                                                                                           ^
```

_note: In this case, the alphabet was only extended once, but this could have been extended multiple times._

Our last hex char `'b'` had an index of `50`, meaning no extension was necessary
and the alphabet was the length of a single hash:

```
d2ee40490a0c4f47994e3539c8d5109f5ad5549a22134e5399b1d2126bf0562d
                                                  ^
```

And that's it! Our final encrypted data is `'5,25,123,50'`.

We then store both the original `encrypt` public parameters and this ciphertext.

### `decrypt` function

But how do we get our data back? By recreating the same alphabets as we did in
the encryption.

"Key" to decryption (pardon the pun) is to start with the same secret and
algorithm parameters. Once started, we can iterate through the indices and
create the alphabets. We do the minimimum number of round functions (recursive
hashes) needed for the index to be valid, i.e. we only extend the alphabet while
index is out of bounds. Once we have a valid index, we dereference it into the
JIT alphabet to give us our plaintext hex character. And once we have decrypted
all of our plaintext hex, we decode from hex to get our original data.

So here is the `decrypt` function, to which we must pass in the same private
`secret` and public parameters `initialRecursions`, `salt`, etc., as in the call
to `encrypt`:

```typescript

async function decrypt({
    encryptedData,                  // '5,25,123,50'
    initialRecursions,             // 2
    recursionsPerHash,             // 2
    salt,                          // 'my salt'
    saltStrategy,                  // 'initialPrepend' means salt only on initialRecursions
    secret,                        // 'my p4ssw0rd'
    hashAlgorithm,                 // 'SHA-256'
    encryptedDataDelimiter,        // ','
}: DecryptArgs): Promise<DecryptResult> {

    let hexEncodedData: string = await decryptToHex({
        encryptedData,
        initialRecursions,
        recursionsPerHash,
        salt,
        saltStrategy,
        secret,
        hashAlgorithm,
        encryptedDataDelimiter,
    }); // '42ab'

    const decryptedData: string = await h.decodeHexStringToString(hexEncodedData);
    // 'foo'

    return { decryptedData ...}
}
```

Inside `decryptToHex` we have the same call to `doInitialRecursions` for
key-stretching to get our starting value of `prevHash` before reconstructing our
first alphabet:

```typescript
let prevHash = await doInitialRecursions({
    secret,
    initialRecursions,
    salt,
    saltStrategy,
    hashAlgorithm,
}); // b87ac03382eb47e692e776547f89b72ea475f0a6dc4848039869b1c93a8ab3ba - the same as in the encrypt phase
```

Notice that our `prevHash` starting point here is the same as in the encryption
phase.  Now with that same starting point we can begin building the alphabets.
But we'll be iterating not through the source hex characters, but through our
encrypted indices:

```typescript
const encryptedDataIndexes: number[] =
    encryptedData.split(encryptedDataDelimiter).map((nString: string) => parseInt(nString));
    // [5,25,123,50] in our example

// for our output
const decryptedDataArray: string[] = [];

// iterate through indices
for (let i = 0; i < encryptedDataIndexes.length; i++) {

    // this is the index of the character of data that we want to get out of the
    // alphabet map...but to generate the alphabet, we may need to do multiple
    // hash rounds, depending on how big the index is. So for a large index, we
    // will need to extend the alphabet accordingly.
    let charIndex = encryptedDataIndexes[i];
    let alphabet: string = "";
    let hash: string;
    while (charIndex >= alphabet.length) {
        for (let j = 0; j < recursionsPerHash; j++) {
            const preHash = getPreHash({prevHash, salt, saltStrategy}); // again the prevHash is used here
            hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
            prevHash = hash;
        }
        alphabet += hash!;
    }

    // we now have each alphabet in turn again, so index into it to get the decrypted hex char
    const hexChar: string = alphabet[charIndex];

    // charIndex: 5
    // alphabet: 519304f9ad8644869e14935607013348865a0ed45a5b46a8b44f78f2256d3f71
    // hexChar: 4

    // charIndex: 25
    // alphabet: 80a53b7e431e43078fddb90ff286939a24a0617d581546c292924dda2574090c
    // hexChar: 2

    // charIndex: 123
    // alphabet: 061899d1b28c46d288b569[70chars...]74330d9c16efec504fcfbc3271cee12a45d2
    // hexChar: a

    // charIndex: 50
    // alphabet: d2ee40490a0c4f47994e3539c8d5109f5ad5549a22134e5399b1d2126bf0562d
    // hexChar: b

    decryptedDataArray.push(hexChar);
}

// reconstitute the decryptedHex
const decryptedHex: string = decryptedDataArray.join('');
// '42ab'
```

Now we decode our hex back into the original string:

```typescript
const decryptedData: string = await h.decodeHexStringToString(hexEncodedData);
// 'foo'
```

And that's it, we have our `decryptedData`!

## attacks

There are always attacks available against encryption algorithms, but again, encrypt-gib
aims to leverage the assumption that cryptographic hashes are "effectively random".

### short-circuit (aka shortcut) brute force attacks

If used in non-multipass mode, encrypt-gib is susceptible to short-circuit brute
forcing, if the brute forcer knows the expected shape that plaintext starts
with, e.g. if it's a JSON object and starts with a `{` character. In this case,
the brute forcer only has to guess secrets against a small subset of the initial
ciphertext. Once a guess is deemed incorrect on the small subset of ciphertext,
they can move on to the next guess, avoiding processing the ciphertext as a
whole.

### sectioned multipass short-circuit mitigation

In order to help mitigate against this, there is a `multipass` parameter that
requires larger blocks of alphabets to be created before decryption (i.e.
dereferencing the index into a JIT alphabet), is possible even for the first
character. This should be used in combination with the `indexingMode` parameter
set to `lastIndexOf`, which will usually force multiple passes to be fully made
even for the very first character.

This works because the multipass mode has a concept of "sections". Each section
is built up with some number of minimal number of passes that extend the
alphabets of each plaintext character in that section as a whole. So given
alphabets a0, a1, ..., an, where n is the character index into that section,
we will extend each alphabet as follows

```
Pass0[a0, a1, ..., an,], Pass1[a00, a11, ..., ann], ..., PassN[a0NNN, a1NNN, ..., anNNN]
```

So each section recursively hashes the `prevHash` from the previous character,
just as in the walkthrough above in the non-multipass stream cipher mode. The
difference is that each alphabet is then automatically extended with other
passes - **even if those alphabets already contain the plaintext hex character to encipher**.

Any additional multipass sections are then concatenated with previous sections
to produce the final encrypted text. Decryption happens the same way, as
alphabets are able to be reconstructed just as in the non-multipass stream mode.

The multipass mitigation technique creates a couple of dynamics:

* More passes requires more processing per character.
* More passes requires either
  * more memory (to keep track of all of the accreting alphabets), OR
  * additional storage and execution time to temporarily store intermediate alphabets
* If ciphertext indices are 0-padded in future implementations, this will be less secure as there will no longer be intermittent, effectively random JIT extended alphabets because odds severely diminish that an alphabet will not contain the plaintext hex character.

_note: so it's conceivable that this could be a memory-hard encryption algorithm a high multipass-count, but this would require analysis and I'm unsure if it could even then be guaranteed._

### timing attacks

Because each cipher round checks for a plaintext character's index into a
cryptographic hash, given that the hash is effectively random, the timing of
indexing into it should not yield any additional information. Intermittent
alphabet extensions, requiring additional round function executions, are also
effectively random.

## todo

* delimit plaintext with params+secret ~~+data~~ derived delimiter
  * enables sectioning within ciphertext, which itself enables...
    * prepending plaintext with noise
    * additional hidden parameters
    * and more...
* auto-generation of salt
  * may require its own IV, or just rely on the runtime's (NodeJS/browser)
    random bytes function.

## running respec-ful tests - `npm test` and others

I recently had a learning experience regarding an extremely popular gate-keeper
style OSS repository. As such, I have moved to my own respec-gib testing
framework, contained in [helper-gib](https://gitlab.com/ibgib/helper-gib).

You can run these respecs via npm scripts contained in encrypt-gib's
[package.json](./package.json).

The main ones are:

* `npm test`
  * ATOW alias for `npm run test:node`
  * runs `node dist/respec-gib.stress-test.node.mjs --inspect`
  * ATOW only node testing implemented
  * runs ALL respecs, which on my now aging laptop took right at 24 hours to run.
* `npm run test:quick`
  * ATOW alias for `npm run test:node:quick`
  * executes a smaller subset of respecs that take much less time.

Since ATOW I don't have respec-gib documented very well (other than explanatory
meta respecs on Gitlab
[here](https://gitlab.com/ibgib/helper-gib/-/blob/main/src/respec-gib/respec-gib.respec.mts)),
you can target only specific respecs by using `respecfullyDear` and `ifWeMight`
functions instead of `respecfully` and `ifWe` blocks, respec-tively. To use
these, ensure that the corresponding respec-gib node file (e.g.
`respec-gib.stress-test.node.mjs`) has the `LOOK_FOR_EXTRA_RESPEC` flag set to
true (ATOW on line 47 of
[`respec-gib.stress-test.node.mts`](./src/respec-gib.stress-test.node.mts)).

### ES Module importmaps when testing with `npm run test:browser`

import maps are not currently implemented in respec-gib. When they are, however,
they will want to generate code as follows:

using **unpkg**:

```html
  <script type="importmap">
    {
      "imports": {
        "@ibgib/helper-gib": "https://unpkg.com/@ibgib/helper-gib@0.0.7/dist/index.mjs",
        "@ibgib/helper-gib/": "https://unpkg.com/@ibgib/helper-gib@0.0.7/"
      }
    }
  </script>
```

**using jsdelivr.net**:

```html
  <script type="importmap">
    {
      "imports": {
        "@ibgib/helper-gib": "https://cdn.jsdelivr.net/npm/@ibgib/helper-gib@0.0.7/dist/index.mjs",
        "@ibgib/helper-gib/": "https://cdn.jsdelivr.net/npm/@ibgib/helper-gib@0.0.7/"
      }
    }
  </script>
```

_note: if you are having CORS issues, it may be due to the cdn being down._

## codebase notes

### length of naming conventions

This codebase prefers `LongAndExplanatoryNames` Pascal-cased for
classes/interfaces/types and most other things camelCased. This is to aid in
readability usually without the need for comments. Extremely short variables are
used though, but only in special cases:

* `lc` - "log context" used in logging
  * this is used more in the ibgib codebase as a whole and ATOW less so in this lib.
* `x` is commonly used in array functions where the type should be evident
  * e.g. `map(x => foo(x))` or `filter(x => !!x)`

### objects for named function parameters

In general, `foo(directVar: SomeType)` is avoided. This is because calling code may
be less readable.

Instead, something like `foo({ name, x, y, }: ArgObjectType)` or
`foo({ name, x, y, }: {name: string, x: number, y: number})`
is used.

## general notes

* ATOW Only UTF-8 data is supported.
* ATOW Nothing is overly optimized for runtime performance.
