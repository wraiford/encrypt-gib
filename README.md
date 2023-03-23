# encrypt-gib white paper

I need some simple encryption. I have no idea how weak this is, but since encryption is so
hard it probably is super weak.

That said, we'll go over the algorithm.

This README will go over the basics of the approach, but there are two better sources: jsdocs in code & the code itself.
So the real "White Paper" would include at least those jsdocs, in case I don't do a good enough job here (never written one).

## tl;dr - up & running

1.  [Clone](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) this repo, [encrypt-gib](https://github.com/wraiford/encrypt-gib/)
2. `npm install` (inside repo folder)
3. `npm test`

You can fiddle around with different types of data/params to test in `encrypt-decrypt.spec.ts`.

## how it works

The basic idea is relatively simple[^1]: Leverage the randomness of hex character
distribution in hashes by creating just-in-time (JIT) "one-time alphabets"
via recursive hashing, and publicly record the indices into those alphabets.

Note that these alphabets are very similar to the keystreams of other stream ciphers,
with the recursive hashing used as the round function. But since the combining function
is not an XOR, and indeed the stream is not at the bit level but the hex level, the term
"alphabet" seems to be more appropriate. The output cipher text is then the accumulation
of these **indices**.

This list of indices ciphertext can then be decrypted into the original by rebuilding the
same alphabets based on the same private secret and other (public!) encryption parameters.

## core implementation

The encryption and decryption code resides in `encrypt-decrypt.ts`.
It exports two public functions: `encrypt` and `decrypt`.

### `encrypt`

There are basically four steps in encryption:

1) Encode our data to hex.
2) Perform `initialRecursions` using `secret` and other algorithm parameters, which gives us our initial hash. (very similar to key stretching)
3) Iterate through the hex data character by character, creating a one-time alphabet for each individual character based on the previous hash (initially created by our secret in step 2)
4) Build up the encrypted data by recording the index for each hex character into that alphabet.

_NOTE: The following code is simplified for the example (removed logging, error handling, validation, etc.) Refer to `encrypt-decrypt.ts` for actual code._

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

So for example, say we have a `secret` of `'my password'` and data of `'foo'`.

First we encode that `'foo'` into hex, pretend it's `'42ab'` (only hex characters here, 0-9, a-f.
We're only pretending this is the actual encoding for this contrived example).
Once encoded, we can represent each character as an index to some alphabet.
If that alphabet is has a "random" distribution of hex characters, like in one single hash
or multiple concatenated hashes, then the index into that distribution also would appear
"as random". So we need to build that random, one-time alphabet.

Each iteration of each character has a starting point of `prevHash`. This is generated via

```typescript
let prevHash = await doInitialRecursions({
    secret,                        // 'my p4ssw0rd'
    initialRecursions,             // 2
    salt,                          // 'my salt'
    saltStrategy,                  // 'initialPrepend' means salt only on initialRecursions
    hashAlgorithm,                 // 'SHA-256'
});
// say, 'b87ac03382eb47e692e776547f89b72ea475f0a6dc4848039869b1c93a8ab3ba'
```

which has the following...

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

So to summarize, we get the extreme starting point for our alphabets (`preHash`) from the
private `secret`, the public `salt` and the `saltStrategy`. We then use this and
`initialRecursions` to produce the "previous" hash (`prevHash`). It's "previous" in the
context of the next iteration loop.

_Note that `initialRecursions` adds a one-time processing cost when encrypting/decrypting._

So with this `prevHash` value, which is just a starting point for
per-hex character alphabet indexing, we can...

1. iterate through each character,
2. build its uniquely random alphabet, and...
3. record the character's uniquely random index into that alphabet

as follows...

```typescript
// we'll store our encrypted results here
let encryptedDataIndexes = [];

// iterate through hex characters: '42ab'
for (let i = 0; i < hexEncodedData.length; i++) {

    // character of data that we want to map to an index into the generated alphabet
    const hexCharFromData: string = hexEncodedData[i];

    // build the one-time alphabet for this character
    // we extend alphabet beyond one hash if the generated hash doesn't contain our character
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
    const charIndex = alphabet.indexOf(hexCharFromData);

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
the first hash alphabet iteration comprises non-`'4'` hex characters only. This is why
we have the `while (!alphabet.includes(hexCharFromData))`. Strictly speaking, it's conceivable
that we will never generate a hash with that character (and thus we won't be able to index
the `hexCharFromData`). But from my testing, the largest alphabet has been 192 characters
(3 alphabet-extending hashes) [^2] and [^3].

So once we have the `alphabet`, we get the index of `hexCharFromData` into that alphabet
and push that `charIndex` to our encrypted results.

Also note here that with `recursionsPerHash`, we execute these recursions
_every alphabet extension_ for every character. So this adds approximately a
linear processing cost to both encrypting and decrypting **but does not increase the alphabet size**.

Once we iterate through all of the hex characters, we create the final `encryptedData`
string value by joining the array by our given `encryptedDataDelimiter`.

For our simplified example, we'll say this is `'5,25,123,50'`, but in testing
this encryption blows up the size of the data by at least a factor of 5x.
Let's look at each index and what it means.

Remember that our encoded hex is `'42ab'`.

For our first character `'4'`, the first index is `5`, which means that
in the hash alphabet, `5` must have been the first index of `'4'`. It also implies that
the alphabet only required one hash iteration
(but that iteration will have hashed `recursionsPerHash` times, in our example's case twice).

So we'll say the first `alphabet` was:

```
519304f9ad8644869e14935607013348865a0ed45a5b46a8b44f78f2256d3f71
     ^
```

Notice here also that there are `'4'`'s after index `5`, but that this was the index of the first occurrence.

The same goes for the next encrypted index value of `25` and `'2'` from our hex:
```
80a53b7e431e43078fddb90ff286939a24a0617d581546c292924dda2574090c
                         ^
```

Now the third index of `123` is different. That it is bigger than our hash length
(64) implies the hash alphabet had to be extended, because it did not have
an `'a'` in the first hash:

```
061899d1b28c46d288b569cc1e3d715cdecf0c1431fb4fb9b61672db5451e76784d9e5d4e36b4495bb76e64bcc2e74330d9c16efec504fcfbc3271cee12a45d2
                                                                                                                           ^
```

In this case, the alphabet was only extended once, but this can be extended multiple times.

Our last hex char `'b'` had an index of `50`, meaning no extension was necessary and the alphabet
was the length of a single hash:

```
d2ee40490a0c4f47994e3539c8d5109f5ad5549a22134e5399b1d2126bf0562d
                                                  ^
```

And that's it! Our final encrypted data is `'5,25,123,50'`.

### `decrypt` function

But how do we get our data back? By recreating the same alphabets as we did in
the encryption.

And the "key" to this (excuse the pun) is to start with the same secret and
algorithm parameters. Once started, we can iterate through the indices and
create the alphabets - extending when necessary with the index being larger than
a single hash size. Leveraging these alphabets, we'll map back to the original
encoded hex characters, and then decode from that hex to our original data.

So in `decrypt` function, we must pass in the same private `secret` and
public parameters `initialRecursions`, `salt`, etc.:

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

Inside `decryptToHex` we have the same call to `doInitialRecursions` to get our
starting value of `prevHash`:

```typescript
let prevHash = await doInitialRecursions({
    secret,
    initialRecursions,
    salt,
    saltStrategy,
    hashAlgorithm,
}); // b87ac03382eb47e692e776547f89b72ea475f0a6dc4848039869b1c93a8ab3ba - the same as in the encrypt phase
```

Notice that our `prevHash` starting point here is the same as in the encryption phase.
Now with that same starting point we can begin building the alphabets. But we'll be iterating
not through the source hex characters, but through our encrypted indices:

```typescript
let encryptedDataIndexes: number[] =
    encryptedData.split(encryptedDataDelimiter).map((nString: string) => parseInt(nString));
    // [5,25,123,50] in our example

// for our output
let decryptedDataArray: string[] = [];

// iterate through indices
for (let i = 0; i < encryptedDataIndexes.length; i++) {

    // this is the index of the character of data that we want to get out of the alphabet map...
    // but to generate the alphabet, we may need to do multiple hash iterations, depending
    // on how big the index is. So for a large index, we will need to extend the alphabet accordingly.
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
    let hexChar: string = alphabet[charIndex];

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

## other code implementation

Here are the other code files of interest.

### `types.ts` and `constants.ts`

These files contain the interfaces and constants used in this lib.
Much of the documentation can be found here.

### `encrypt-decrypt.spec.ts`

Here is where you can fiddle with testing of different parameters of the
`encrypt` and `decrypt` functions. But remember it's easy to set too many tests
for your computer to run depending on the parameters and data you choose!

### `helper.ts`

It contains helper/util functions like `getUUID` and `hash`, as well as the functions
related to converting to/from hex.

## future improvements

Though I'm not sure of this project's overall viability vis-a-vis hash-based encryption,
there are many improvements that can be implemented if it seems worth it.

These are largely to increase security based on the fact that if an attacker begins to guess,
it can look for informational non-entropy to get an early feedback for correctness of the guess.
In other words, it won't have to decrypt the entire data if it get's sensical data for the first N characters.
So there are several things we can do to mitigate this partial decryption hacking.

* "Buffering" the data in such a way that would make brute-forcing it harder to do.
  * E.g., hashing the data itself and prepending the data with this hash (or recursive chains of hashes)
    before encrypting to create a random-looking starting buffer.
  * it would be better to have a hash that produces not just hex, but all UTF-8 characters.
    * Perhaps "unencode" the checksum hex hash chain.
* "Bloating" the encrypted data.
  * You can spread out data by creating search parameters for the encrypt/decrypt process.
  * E.g., whenever some set of neighbors of the output condition is met, then that encryption step
    is invalid and repeated, and the corresponding decryption step would see it as invalid and discarded.
    * It's possible that these conditions can be contained at the end of the data as metadata that requires
      decrypting all data in order to see what bloating rules are in effect.
      * (I think those bloating rules would have to not be bloated themselves.)
* "Recursive" encrypting/decrypting.
  * Similar to the other improvements, this might actually be of some benefit in mitigating partial
    decryption attacks.
* and others along these lines...

## investing time and/or $

During my 42 years of human-ness, I've had one obsession that I have yet to escape:
ibgib ([GitHub ibgib MVP monorepo](https://github.com/wraiford/ibgib) &
[npm ts-gib DLT graph substrate](https://www.npmjs.com/package/ts-gib)).
The current main MVP app is the [`ionic-gib` project](https://github.com/wraiford/ibgib/tree/master/ionic-gib)
which aims to leverage ibgib's unique data capabilities with [ionic](https://ionicframework.com/) to target
not only web, android and iOS, but also even Chrome, FireFox, Edge and other browser extensions.

If you find this little encrypt-gib project,
which I whipped up in three days, to be interesting, don't hesitate to contact me.
An issue for public discussion would be best either at
[ibgib's issues](https://github.com/wraiford/ibgib/issues)
or in this repo
[encrypt-gib issues](https://github.com/wraiford/encrypt-gib/issues).
But you can also find my email address on my GitHub profile for [wraiford](https://github.com/wraiford).

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
* Obviously none of this is hyper-optimized for performance.

## footnotes

[^1] so simple, I'm sure someone here on Earth must have done this before...but I can't find it on the interweb.

[^2] perhaps there is a mathematical proof covering these probabilities.

[^3] I generally avoid using `while` loops when I can do a `for`, but it's a first implementation.
