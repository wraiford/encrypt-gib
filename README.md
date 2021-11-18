# encrypt-gib "White Paper"

I need some simple encryption. I have no idea how weak this is, but since encryption is so
hard it probably is super weak.

That said, we'll go over the algorithm.

This README will go over the basics of the approach, but there are two better sources: jsdocs in code & the code itself.
So the real "White Paper" would include at least those jsdocs, in case I don't do a good enough job here (never written one).

## how it works

The basic idea is relatively simple[^1]: Leverage the randomness of hex character
distribution in hashes by creating just-in-time (JIT) "one-time alphabets"
via recursive hashing, and publicly record the indices into those maps.

This list of indices can then be decrypted into the original by rebuilding the
same alphabets based on the same private secret and other (public!) encryption parameters.

### assumptions

* data to be encrypted can in some way be converted to hex deterministically
  * that produced hex is no more "known" beforehand than the original data to be encrypted
  * the data can be reproduced from that hex deterministically
* hashing is still hard to pre-image
  * recursive hashing many times is even harder to pre-image
* hashes produce relatively random distributions of hexadecimal characters
  * a hash based on a secret + salt, and expanded via some deterministic function
    (e.g. recursive hashing, salting, etc., compositions),
    provides a "JIT one-time alphabet" at least as "unknowable" as the hash itself.
    * continuous expansion (recursive hashing) will eventually produce each of the hexadecimal characters.
  * we can leverage the "one-time-ness" of each alphabet and _publicly_ show _the index_
    of the encrypted hex character into the next one-time alphabet expansion.

## code implementation

### `encrypt-decrypt.ts`

This is where the actual encryption/decryption algorithm resides. It exposes two functions: `encrypt` and `decrypt`.

#### `encrypt`

There are basically four steps in encryption:

1) Encode our data to hex.
2) Perform `initialRecursions` using `secret` and other algorithm parameters, which gives us our initial hash.
3) Iterate through the hex data character by character, creating a one-time alphabet for each individual character based on the previous hash (initially created by our secret in step 2)
4) Build up the encrypted data by recording the index for each hex character into that alphabet.

So for example, say we have a `secret` of `'my password'` and data of `'42 foo'`.

First we encode that `'42 foo'` into hex, say `'42abc'` (I'm just including 42 for learning purposes, the actual hash of course has no correlation). Once encoded, we can represent each
character as an index to some alphabet. (If that alphabet is "random"ly distributed of hex
characters, like in one single hash or multiple concatenated hashes, then the index into that
distribution also appears "as random".) So we need to build that random alphabet.

Each iteration of each character has a starting point of `prevHash`. This is generated via
```typescript
let prevHash = await doInitialRecursions({
    secret,                        // 'my p4ssw0rd'
    initialRecursions,             // 2
    salt,                          // 'my salt'
    saltStrategy: saltStrategy!,   // 'initialPrepend' means salt only on initialRecursions
    hashAlgorithm: hashAlgorithm!, // 'SHA-256'
});
```
```typescript
// error handling removed
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
which relies on `getPreHash`:
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

Note that `initialRecursions` adds a one-time processing cost when encrypting/decrypting.

So at this point, we have a `prevHash` value, which is just a starting point for
per-hex character alphabet indexing.

Now we can iterate through each character, build its uniquely random alphabet, and
record the character's uniquely random index into that alphabet:

```typescript
let encryptedDataIndexes = [];
for (let i = 0; i < hexEncodedData.length; i++) { // iterate through characters
    // this is the character of data that we want to map to an index into the generated alphabet
    const hexCharFromData: string = hexEncodedData[i];
    let alphabet: string = "";
    let hash: string;
    while (!alphabet.includes(hexCharFromData)) {
        for (let j = 0; j < recursionsPerHash; j++) {
            const preHash = getPreHash({prevHash, salt, saltStrategy});
            hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
            prevHash = hash;
        }
        alphabet += hash!;
    }

    // we now have the alphabet, so find the index of hex character
    const charIndex = alphabet.indexOf(hexCharFromData);
    // console.log(`${lc} charIndex: ${charIndex}`);
    encryptedDataIndexes.push(charIndex);
}

const encryptedData = encryptedDataIndexes.join(encryptedDataDelimiter);
return encryptedData;
```

Now say our `hexCharFromData` has a value of `'a'`. There is a possibility that
the first hash alphabet iteration comprises non-`'a'` hex characters only. This is why
we have the `while (!alphabet.includes(hexCharFromData))`. Strictly speaking, it's conceivable
that we will never generate a hash with that character. But from my testing, the most this
happens is at 192 characters (3 alphabet-extending hashes) [^2] and [^3].

So once we have the `alphabet`, we get the index of `hexCharFromData` into that alphabet
and push that `charIndex` to our encrypted results.

Also note here that with `recursionsPerHash`, we execute these recursions
_every alphabet extension_ for every character. So this adds approximately a
linear processing cost to both encrypting and decrypting.

Once we iterate through all of the hex characters, we create the final `encryptedData`
string value by joining the array by our given `encryptedDataDelimiter` (`','` atow).

For our simplified example, we'll say this is `'5,25,123,50'`, but in testing
this encryption blows up the size of the data by at least a factor of 5x.

#### `decrypt`

So now, we have our encrypted data of `'5,25,123,50'`. How do we get our data back?

Basically, the key is reproducing the exact same alphabet hashes. We'll convert the
encrypted data back to the hex, and then we'll decode from hex to our original data.

So in `decrypt` function, we must pass in the same parameters `initialRecursions`, `salt`, etc.:

```typescript
let hexEncodedData: string = await decryptToHex({
    encryptedData,
    initialRecursions,
    recursionsPerHash,
    salt,
    saltStrategy,
    secret,
    hashAlgorithm,
    encryptedDataDelimiter,
});
```

which has inside, the same call to `doInitialRecursions`:

```typescript
let prevHash = await doInitialRecursions({
    secret,
    initialRecursions,
    salt,
    saltStrategy: saltStrategy!,
    hashAlgorithm: hashAlgorithm!,
});
```

Once we have our `prevHash`, we iterate again - only this time, not through the source
hex characters, but through our encrypted indices (with the delimiters removed):

```typescript
let encryptedDataIndexes: number[] =
    encryptedData.split(encryptedDataDelimiter).map((nString: string) => parseInt(nString));
let decryptedDataArray: string[] = [];
for (let i = 0; i < encryptedDataIndexes.length; i++) {
    // this is the index of the character of data that we want to get out of the alphabet map
    // but to generate the alphabet, we may need to do multiple hash iterations, depending
    // on how big the index is. So if we don't hit a '7' until the third hash, then we need to
    // keep building out the alphabet until that third hash.
    let charIndex = encryptedDataIndexes[i];
    let alphabet: string = "";
    let hash: string;
    while (charIndex >= alphabet.length) {
        for (let j = 0; j < recursionsPerHash; j++) {
            const preHash = getPreHash({prevHash, salt, saltStrategy});
            hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
            prevHash = hash;
        }
        alphabet += hash!;
    }

    // we now have the alphabet, so index into it to get the decrypted hex char
    let hexChar: string = alphabet[charIndex];
    decryptedDataArray.push(hexChar);
}

// reconstitute the decryptedHex
const decryptedHex: string = decryptedDataArray.join('');
```

Now we decode our hex back into the original string:

```typescript
const decryptedData: string = await h.decodeHexStringToString(hexEncodedData);
```

And that's it, we have our `decryptedData`.

### node vs. browser targets

I've found difficulty implementing "isomorphic" JS packages that contain crypto functions.
So I've hacked together `set_target.sh` that generates code files from any source files that are...

1) Listed in the files array in `set_target.sh`, and
2) have the filename end in `*.node.ts` or `*.browser.ts`

For example, the `helper.ts` is actually auto-generated from the corresponding `helper.node.ts` or `helper.browser.ts`
depending on the build target.

The complexity is mitigated by using `npm run` scripts. See `package.json` or run `npm run` for build options.

My solution feels less than ideal, but it's the best I can do right now.

### `helper.ts`

Again, this is auto-generated from `helper.node.ts` and `helper.browser.ts`.

It contains helper/util functions like `getUUID`, `hash`, and functions related to converting to/from hex.

### `types.ts` and `constants.ts`

These files contain the interfaces and constants used in this lib.
Much of the documentation can be found here.

### `encrypt-decrypt.spec.ts`

Here is where you can fiddle with testing of different parameters of the
`encrypt` and `decrypt` functions.

## future

There are many improvements that I can think of off the top of my head, but I'm not sure of their utility or
even the overall viability of the hash-based approach:

* "Stretching" the data in such a way that would make brute-forcing it harder to do.
  * E.g., hashing the data itself and prepending the data with this hash before encrypting.
* "Bloating" the encrypted data.
  * E.g.,

## notes

* Only UTF-8 data supported.
  * I'm not expert enough to count on anything other than the basic characters in the test specs.
* I use `lc` all over the place in code. I am usually not for single-letter or extremely
  short variable/function/class/etc names, but I use this so often the brevity is worth the readability cost.
  * Plus, you can tell it's used for logging pretty easily.
* I return function parameters in result objects, and consequently it's a pain to add/remove params.
  * May want to fix this in the future, but...
  * But the ibgib architecture (which is paramount) is about building DLT encoding of these
    types of parameters, so I haven't fixed it first go-round.
* I've left in a lot of commented-out console.log calls. These take a bit to re-type.
  * THE MOST IMPORTANT THING IS DON'T LOG ANYTHING TO DO WITH DATA PROPERTIES IN PROD!
* I'm currently using node v16.

## footnotes

[^1] so simple, I'm sure some earthling must have done this before...but I can't find it on the interweb.

[^2] perhaps there is a mathematical proof covering these probabilities.

[^3] I generally avoid using `while` loops when I can do a `for`, but it's a first implementation!
