**:warning: This is experimental. No guarantees are made or implied regarding its qualities, including but not limited to, its strength, speed, storage overhead. Use at your own risk.**

# encrypt-gib - hash-based encryption at the hex level

Encrypt-gib is a novel, post quantum, symmetric encryption algorithm candidate
that uses cryptographic hashes as its only magical primitive, combined with
moderately simple programming.

The key differentiation of this algorithm is that it leverages crytographic
hashes more extensively than in any other system. It functions as a substitution
cipher at the hex level, sacrificing perfomance in conventional metrics such as
speed and storage size in order to reduce overall complexity - DRYer code with
more understandable implementation details.

There exists a weaker but faster stream mode, as well as a stronger but slower multipass block mode which also produces more storage overhead.

## tl;dr - up & running

You can use the library directly from the npm package, or if you're interested
in playing with the code and parameters more interactively, follow the steps for
development.

### request line interface

Encrypt-gib's RLI is a work in progress. You can use it via a global install:

1. `npm install --global @ibgib/encrypt-gib`
2. `encrypt-gib --help`

_note: the term "request line interface" itself is in line with my vision of a more dynamic, vibrant, and more boldly polite future for distributed computation._

Or you can clone the repo and use `node .` in the repo's base folder, in place
of `encrypt-gib`, e.g. `node . --help`

### development

1.  [Clone](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) this repo, [encrypt-gib](https://github.com/wraiford/encrypt-gib/)
2. `cd encrypt-gib`
2. `npm install`
3. `npm run test:quick` OR `npm test` if you want to sit around for hours admiring ibgib's custom respec-gib testing framework.
  * _note: ATOW with testing framework reshuffle to respec-gib, this only runs node tests - not browser tests._

You can find API usage examples in the following respecs:

* [`encrypt-decrypt.light.respec.mts`](./src/encrypt-decrypt.light.respec.mts)
* [`encrypt-decrypt.heavy.respec.mts`](./src/encrypt-decrypt.heavy.respec.mts)
* [`encrypt-decrypt.mitigation.respec.mts`](./src/encrypt-decrypt.mitigation.respec.mts)

## how it works

The basic idea is this:

> Use configurable recursive cryptographic hashes for effectively random,
> one-time, just-in-time (JIT) alphabets and substitute **indices** into these
> alphabets as our ciphertext.

```
plaintext: "a"

plaintext (hex): 61

plaintext (hex) char: 6
alphabet #1:
5965e6cfcf0f...
  ^
ciphertext (index): 2

plaintext (hex) char: 1
alphabet #2:
7546c9b481be...
         ^
ciphertext character (index): 9

total ciphertext:
2,9
```

 These are dynamically sized, hex-based alphabets that act
as dynamic 1-time pads for substitution and not as keystreams used in binary
combining functions.

So our ciphertext is built by substituting a plaintext hex character with its
index into a hash "alphabet". We generate these alphabets in stream mode by
recursive hashing (with parameters deciding details).

There are a couple things to note immediately:

1. This operates as a **substitution** cipher at the hex level, not at the binary level. As such, this is not a keystream and combining functions such as XOR or others are not available or required for additional confusion. The randomness of the hash itself is the confusion.
2. The initial keystretching phase also uses the same round function that performs the recursive hashing, keeping the implementation DRY-er.
3. Due to the non-zero probability of a single hash containing any given hex character, individual alphabets may be built with multiple concatenated hashes.
4. Decryption occurs by the same construction of alphabets, but dereferencing the indices in the alphabet to reverse the substitution.

The current implementation supports either SHA-256 and SHA-512 as parameters,
because both are available in NodeJS and the browser to maximize isomorphic
JavaScript. Conceptually, this could use any cryptographic hash or other
function, as long as that function can deterministically build string
concatenations into which we can index our plaintext.

This index-based ciphertext can then be decrypted into the original by
reconstructing the same alphabets based on the same private secret and other
public encryption parameters. We then de-reference the ciphertext indices back
into plaintext hex and finally decode to our original data.

## core implementation - stream mode

_note: This is a description of the stream mode of the algorithm. This does not mean it is a stream-only algorithm. See the block section below for a variable-block construction._

The encryption and decryption code resides in `encrypt-decrypt.ts`.  It exports
two public functions: `encrypt` and `decrypt`.

Here is a walkthrough of the stream-only encrypt and decrypt processes.

_note: The following code is simplified for the example (removed logging, error handling, validation, etc.) Refer to [`encrypt-decrypt.ts`](./src/encrypt-decrypt.mts) for actual code._

### `encrypt`

There are basically four steps in encryption:

1) Encode our data to hex.
2) Perform key-stretch via `initialRecursions` using `secret` and other algorithm parameters, which gives us our starting point for our first alphabet.
3) Iterate through the hex data character by character, creating a one-time alphabet for each individual character based on the previous hash.
4) Record index of plaintext hex character in alphabet, using either `indexOf` or `lastIndexOf` (public parameter), aggregating our ciphertext with each successive index.

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
let prevHash = await doInitialRecursions_keystretch({
    secret,                        // 'my p4ssw0rd'
    initialRecursions,             // 2
    salt,                          // 'my salt'
    saltStrategy,                  // 'initialPrepend' means salt only on initialRecursions
    hashAlgorithm,                 // 'SHA-256'
});
// the last hash after initial recursions, say, 'b87ac03382eb47e692e776547f89b72ea475f0a6dc4848039869b1c93a8ab3ba'


async function doInitialRecursions_keystretch({
    secret,
    initialRecursions,
    salt,
    saltStrategy,
    hashAlgorithm,
}:... ): Promise<string> {
    const hash = await execRound_getNextHash({
        secret,
        count: initialRecursions,
        salt, saltStrategy, hashAlgorithm,
    })
    return hash;
}
```

This relies on the same round function used in encryption/decryption, [`execRound_getNextHash`](./src/common/encrypt-decrypt-common.mts)...

```typescript
export async function execRound_getNextHash({
    secret,
    prevHash,
    count,
    salt,
    saltStrategy,
    hashAlgorithm,
}:...): Promise<string> {
  let hash = prevHash || undefined;
  for (let i = 0; i < count; i++) {
      const preHash = getPreHash({ secret, prevHash: hash, salt, saltStrategy });
      hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
  }
  return hash;
}

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

// parameter determines how to substitute ciphered index for plaintext character
const getIndex: (alphabet: string, hexChar: string) => number =
    indexingMode === 'indexOf' ?
        (alphabet: string, hexChar: string) => { return alphabet.indexOf(hexChar) } :
        (alphabet: string, hexChar: string) => { return alphabet.lastIndexOf(hexChar) };

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
        hash = await execRound_getNextHash({
            count: recursionsPerHash,
            prevHash, salt, saltStrategy, hashAlgorithm
        });
        alphabet += hash!;
        prevHash = hash;
    }

    // we now have the alphabet, so find the index of hex character
    // either `indexOf` or `lastIndexOf` into alphabet
    // we use `indexOf` in this example
    const charIndex = getIndex(alphabet, hexCharFromData);

    // hexChar: 4
    // alphabet: 519304f9ad8644869e14935607013348865a0ed45a5b46a8b44f78f2256d3f71
    //                ^
    // charIndex: 5 (first index of 4)

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

Inside `decryptToHex` we have the same call to `doInitialRecursions_keystretch` for
key-stretching to get our starting value of `prevHash` before reconstructing our
first alphabet:

```typescript
let prevHash = await doInitialRecursions_keystretch({
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
        hash = await execRound_getNextHash({
            count: recursionsPerHash,
            prevHash, salt, saltStrategy, hashAlgorithm
        });
        alphabet += hash;
        prevHash = hash;
    }

    // we now have each alphabet in turn again, so index into it to get the decrypted hex char
    const hexChar: string = alphabet[charIndex];
    decryptedDataArray.push(hexChar);

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

And that's it, we have our `decryptedData`.

## core implementation - block mode `encrypt`

The block mode acts similarly to the stream mode, but with a few key exceptions:

1. The hex plaintext is divided into a maximum sized "sections".
  * These are similar to "blocks", but they do not have to be the same size and the final block does not have to be padded.
2. Each section's alphabets are constructed via a configurable number of passes. Each character's alphabet is extended only once per pass, and each is extended a minimum number of the pass count parameter.
  * So a ciphertext's index cannot be deciphered (i.e. when brute-force guessing) until the entire alphabet is constructed, and the entire alphabet's construction depends on the previously executed rounds.

So here is a walkthrough of the block mode. In this case, I'll add actual
algorithm execution, as I've enabled verbose logging.

_note: I will just cover the encrypt, as the decrypt works the same way as the stream version._

ATOW here is the commandline I used, in the root folder after building via `npm run build`:

```
node . --encrypt --data-string="foo" --output-path="./foo.encrypt-gib" --indexing-mode="lastIndexOf" --salt-strategy="prependPerHash" --hash-algorithm="SHA-256" --salt="salt123" --initial-recursions="1000" --blockMode --block-size="2" --num-of-passes="3"
```

Let's pick this up in execution at
[`encrypt-from-hex-block-mode.mts`](./src/block-mode/encrypt-from-hex-block-mode.mts),
at which point we have already done initial validation of parameters, as well as
hex-encoded the plaintext. Here is the first part (again with logging etc. removed):

```typescript
let prevHash = await doInitialRecursions_keystretch({
    secret,                         // foo
    initialRecursions,              // 1000
    salt,                           // salt123
    saltStrategy: saltStrategy!,    // prependPerHash
    hashAlgorithm: hashAlgorithm!,  // SHA-256
});
```

So `doInitialRecursions_keystretch` is our key-stretching, the same as in the stream version.

Next we set our `AlphabetIndexingMode` function:

```typescript
const getIndexOfCharInAlphabet: (alphabet: string, hexChar: string) => number =
    indexingMode === 'indexOf' ?
        (alphabet: string, hexChar: string) => { return alphabet.indexOf(hexChar) } :
        (alphabet: string, hexChar: string) => { return alphabet.lastIndexOf(hexChar) };

// getIndexOfCharInAlphabet is (alphabet, hexChar) => { return alphabet.lastIndexOf(hexChar); }
```

In block mode, we want to use the `'lastIndexOf'` version. We'll go into why this is later.
For now, the next block of code:

```typescript
let encryptedDataIndexes: number[] = [];                     // empty to start with
let totalLength = hexEncodedData.length;                     // 6
let blockSize = maxBlockSize;                                // 2
let blockSections = Math.ceil(totalLength / blockSize);      // 3 sections
let finalBlockSize = (totalLength % blockSize) || blockSize; // 2
let indexHexEncodedDataAtStartOfPass = 0;
```

This prepares for executing the multipass blocks. The `encryptedDataIndexes`
is our ciphertext in the form of a JS array. The other variables will be used in
iterating across the plaintext hex data. For our example, the total hex length
is 6, which is evenly divisible by the section length 2, to give us a total of 3
sections.

Let's look at the details of that multipass block iteration, as that is the guts
of the strategy:

```typescript
for (let indexOfBlock = 0; indexOfBlock < blockSections; indexOfBlock++) {

    // adjust the blockSize if it's the final one which might be shorter
    const isFinalBlock = indexOfBlock === blockSections - 1;
    if (isFinalBlock) { blockSize = finalBlockSize; }

    // build all of the alphabets for the section (heart of block strategy)
    const resGetAlphabets = await getAlphabetsThisBlock({
        blockSize, indexHexEncodedDataAtStartOfPass,
        numOfPasses, hexEncodedData, recursionsPerHash,
        salt, saltStrategy, prevHash, hashAlgorithm,
    });

    let alphabetsThisBlock = resGetAlphabets.alphabetsThisBlock;
    // we always keep track of the prevHash, as this is used in each round function
    prevHash = resGetAlphabets.prevHash;

    // now that we have the alphabets, we can do our index substitution for each
    // character in the section.
    const encryptedIndexesThisBlock = await getEncryptedIndexesThisBlock({
        alphabetsThisBlock, blockSize,
        indexHexEncodedDataAtStartOfPass, hexEncodedData,
        numOfPasses, getIndexOfCharInAlphabet,
    });

    // add this section's ciphertext indices to the total output
    encryptedDataIndexes = encryptedDataIndexes.concat(encryptedIndexesThisBlock);

    // adjust our offset for the next section
    indexHexEncodedDataAtStartOfPass += blockSize;
}
```

So the essential part of this code is the `getAlphabetsThisBlock` call. This
is where we construct our alphabets differently than in stream mode. The rest of
the code is relatively self-explanatory, so let's look at `getAlphabetsThisBlock`:

```typescript
async function getAlphabetsThisBlock(...): Promise<{ alphabetsThisBlock: string[], prevHash: string }> {
    let alphabetsThisBlock: string[] = [];
    let indexHexEncodedData: number;
    let hash: string;
    // first construct ALL alphabets for this pass section using the
    // given number of passes. Note that zero or more of these alphabets
    // may NOT include the hex character to encode, but this will be
    // addressed in the next step.
    for (let passNum = 0; passNum < numOfPasses; passNum++) {
        for (let indexIntoBlock = 0; indexIntoBlock < blockSize; indexIntoBlock++) {
            indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoBlock;
            let alphabet = alphabetsThisBlock[indexIntoBlock] ?? '';
            hash = await execRound_getNextHash({
                count: recursionsPerHash,
                prevHash, salt, saltStrategy, hashAlgorithm
            });
            alphabet += hash;
            prevHash = hash;
            alphabetsThisBlock[indexIntoBlock] = alphabet;
        }
    }

    // at this point, each alphabet is the same size (numOfPasses * hash
    // size), but it's not guaranteed that each alphabet will contain the
    // plaintext character. so go through and extend any alphabets that do
    // not yet contain the plaintext character
    for (let indexIntoBlock = 0; indexIntoBlock < blockSize; indexIntoBlock++) {
        indexHexEncodedData = indexHexEncodedDataAtStartOfPass + indexIntoBlock;
        const hexCharFromData: string = hexEncodedData[indexHexEncodedData];
        let alphabet = alphabetsThisBlock[indexIntoBlock];
        while (!alphabet.includes(hexCharFromData)) {
            hash = await execRound_getNextHash({
                count: recursionsPerHash,
                prevHash, salt, saltStrategy, hashAlgorithm
            });
            alphabet += hash!;
            prevHash = hash;
        }
        alphabetsThisBlock[indexIntoBlock] = alphabet;
    }

    // at this point, each alphabet is at least the minimum size and is
    // guaranteed to have at least once instance of the plaintext hexChar.
    // we also return prevHash for use in the next section is applicable.
    return { alphabetsThisBlock, prevHash };
    // ...
}
```

So here is the real core of the multipass block strategy. The point is that
since we iterate over the entire section, we cannot create the early alphabets
without going through each round function of the characters later in the
section. This is why it is important to use the `lastIndexOf` in the
enciphering, to fully utilize the multipass extensions of each alphabet.

For our walkthrough example, here is the output of how the alphabets are constructed:

```
info: {
  "blockSize": 2,
  "numOfPasses": 3,
  "indexHexEncodedDataAtStartOfPass": 0,
  "prevHash": "b52d06e35b980303bc9615d27298e8ff3957ee681602ff3f87fd7dc7905b8c06"
}

```

So notice here that we have the `prevHash` of
`"b52d06e35b980303bc9615d27298e8ff3957ee681602ff3f87fd7dc7905b8c06"`. This is
the starting point, plus our salt strategy that will generate the next alphabet.

Here is the first alphabet extension for the first character in the section.
Note that we don't care about the plaintext hex character yet, as these are the
minimum-sized alphabets per our block parameters.

```
passNum: 0, indexIntoBlock: 0
starting alphabet:
extended alphabet: e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c74
alphabetsThisBlock: [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c74"
]
```

So this means that for our first pass in our first section, our **partial**
alphabet is
`"e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c74"`.

```
passNum: 0, indexIntoBlock: 1
starting alphabet:
extended alphabet: 4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459
alphabetsThisBlock: [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c74",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459"
]
```

Here, we've done the first alphabet segment for the second character. Since our section
size is 2 in this example, we are done with this pass. Now we will increment our `passNum`
and extend each alphabet in the section:

```
passNum: 1, indexIntoBlock: 0
starting alphabet: e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c74
extended alphabet: e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d01
alphabetsThisBlock: [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d01",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459"
]
```
Now notice that the first alphabet in the section is a length of 2 hash digests, while the second alphabet is still only
one in length. This is because we extended the first alphabet...**but only after completing the previous pass**. We had to first
perform our recursive hashing on `prevHash` for the second character in the section before we could extend the alphabet for our
first character.

This is the primary aspect of what helps mitigate against short-circuit brute forcing.

Here is the next alphabet extension:

```
passNum: 1, indexIntoBlock: 1
starting alphabet: 4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459
extended alphabet: 4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be90
alphabetsThisBlock: [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d01",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be90"
]
```

At this point, we have completed our (very short for pedantic reasons) second pass. Note that our alphabets are uniformly 2
hash digests in length. Here is the output from the third and final pass:

```
passNum: 2, indexIntoBlock: 0
starting alphabet: e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d01
extended alphabet: e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d017a1bdb0a395fd85b1c33c7434b6f9295ee0986ff080238fde230a865c43d57e8
alphabetsThisBlock: [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d017a1bdb0a395fd85b1c33c7434b6f9295ee0986ff080238fde230a865c43d57e8",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be90"
]
passNum: 2, indexIntoBlock: 1
starting alphabet: 4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be90
extended alphabet: 4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be904331789be106a17b1f0149e36bc615312fc53b340ac416f80484be2d529e6bd9
alphabetsThisBlock: [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d017a1bdb0a395fd85b1c33c7434b6f9295ee0986ff080238fde230a865c43d57e8",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be904331789be106a17b1f0149e36bc615312fc53b340ac416f80484be2d529e6bd9"
]
```
At this point, in addition to the aspect of the need to compute other hashes,
note that we must also keep track of the other hashes in the section.  Either
this will cost in terms of memory or in terms of processing+I/O (for overhead of
temporary storage/retrieval of alphabets). For example, if you have a high
number of passes (say 100), then for each section you not only have to execute a
larger number of hashes, but also you have to somehow maintain all of the
alphabet extensions for the entire section.

So we now have two alphabets that each correspond to our two plaintext hex
characters. BUT, zero or more these alphabets may not contain its corresponding
plaintext character. This is the purpose of the second inner `for` loop. This
additional step guarantees and extends _only those alphabets that require
extending_. The larger the `numOfPasses`, the larger the alphabets, and
consequently the less likely the probability of needing to extend. In our case,
our data is too small to require any ad hoc extensions.

```
initial alphabetsThisBlock (2): [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d017a1bdb0a395fd85b1c33c7434b6f9295ee0986ff080238fde230a865c43d57e8",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be904331789be106a17b1f0149e36bc615312fc53b340ac416f80484be2d529e6bd9"
]

// at this point, each alphabet is the same size (numOfPasses * hash size), but it's not guaranteed that each alphabet will contain the plaintext character.  so go through and extend any alphabets that do not yet contain the plaintext character
alphabetsThisBlock (length 2): [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d017a1bdb0a395fd85b1c33c7434b6f9295ee0986ff080238fde230a865c43d57e8",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be904331789be106a17b1f0149e36bc615312fc53b340ac416f80484be2d529e6bd9"
]

// no change because no extension required
alphabetsThisBlock (length 2): [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d017a1bdb0a395fd85b1c33c7434b6f9295ee0986ff080238fde230a865c43d57e8",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be904331789be106a17b1f0149e36bc615312fc53b340ac416f80484be2d529e6bd9"
]

// guaranteed now
guaranteed alphabetsThisBlock (2): [
  "e6d56fa02289b992a6cc5845a3c9af596cf8617239b5fa9720d2227c27e44c7415485d12a2ecfb19624acad949dd5194b2cf4c17759cd81c6648c982a1499d017a1bdb0a395fd85b1c33c7434b6f9295ee0986ff080238fde230a865c43d57e8",
  "4da38fc7ae8c5ee4f86476a34b3faf05d796e57c967ee11325914ea4a194a459e84a4fc843478f646356d9efa5368a58eb9666148d843e4b9a5b201f6653be904331789be106a17b1f0149e36bc615312fc53b340ac416f80484be2d529e6bd9"
]
at this point, each alphabet is at least the minimum size and is guaranteed to have at least once instance of the plaintext hexChar.
```

Lastly, we return both the alphabets and our last generated `prevHash`, because we will use
that `prevHash` in the next section. Here I also am logging the encrypted indices
both for this section and total:

```
return prevHash: 4331789be106a17b1f0149e36bc615312fc53b340ac416f80484be2d529e6bd9
encryptedIndexesThisBlock: 182,188
encryptedDataIndexes so far: 182,188
```

This completes the first section. The second two in our walkthrough example work
the same way (skip this if you already understand the algorithm):

Here is the next section's output:

```
info: {
  "blockSize": 2,
  "numOfPasses": 3,
  "indexHexEncodedDataAtStartOfPass": 2,
  "prevHash": "4331789be106a17b1f0149e36bc615312fc53b340ac416f80484be2d529e6bd9"
}
```

So we are about to start the next section. Note that here `prevHash` is the same
as our above returned `prevHash`. Also, we are indexing into the hex plaintext
corresponding to the next sections starting index.

Here is the rest of the second section:

```
passNum: 0, indexIntoBlock: 0
starting alphabet:
extended alphabet: af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351
alphabetsThisBlock: [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351"
]
passNum: 0, indexIntoBlock: 1
starting alphabet:
extended alphabet: 90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acd
alphabetsThisBlock: [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acd"
]
passNum: 1, indexIntoBlock: 0
starting alphabet: af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351
extended alphabet: af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f
alphabetsThisBlock: [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acd"
]
passNum: 1, indexIntoBlock: 1
starting alphabet: 90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acd
extended alphabet: 90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac
alphabetsThisBlock: [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac"
]
passNum: 2, indexIntoBlock: 0
starting alphabet: af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f
extended alphabet: af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f568134dc23212d55d35936b89488a81de25269da5637aa32d457599449d378e0
alphabetsThisBlock: [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f568134dc23212d55d35936b89488a81de25269da5637aa32d457599449d378e0",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac"
]
passNum: 2, indexIntoBlock: 1
starting alphabet: 90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac
extended alphabet: 90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c
alphabetsThisBlock: [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f568134dc23212d55d35936b89488a81de25269da5637aa32d457599449d378e0",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c"
]
initial alphabetsThisBlock (2): [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f568134dc23212d55d35936b89488a81de25269da5637aa32d457599449d378e0",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c"
]
at this point, each alphabet is the same size (numOfPasses * hash size), but it's not guaranteed that each alphabet will contain the plaintext character.  so go through and extend any alphabets that do not yet contain the plaintext character
alphabetsThisBlock (length 2): [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f568134dc23212d55d35936b89488a81de25269da5637aa32d457599449d378e0",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c"
]
alphabetsThisBlock (length 2): [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f568134dc23212d55d35936b89488a81de25269da5637aa32d457599449d378e0",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c"
]
guaranteed alphabetsThisBlock (2): [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f568134dc23212d55d35936b89488a81de25269da5637aa32d457599449d378e0",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c"
]
at this point, each alphabet is at least the minimum size and is guaranteed to have at least once instance of the plaintext hexChar.
return prevHash: 711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c
[encryptFromHex_blockMode] alphabetsThisBlock: [
  "af097e0a21ee86c3da614e84d7a9d7db5ecd712e893bc930e5d3a8d4ca22b351b7ab46d7843546c73b3b57dd84c50f1c484a972375e88101458a3fdf79ebc33f568134dc23212d55d35936b89488a81de25269da5637aa32d457599449d378e0",
  "90b76a58bc1eea77cd2301f04422eb3d6715b80529b25efd203fe54a1ddb3acdba1dd5ffe6bee38c368778be7f06322dd93f24f13ba93920ab07f39aba16c6ac711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c"
]
prevHash after alphabets created: 711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c
encryptedIndexesThisBlock: 169,184
encryptedDataIndexes so far: 182,188,169,184
```

So the second section added two more indices.

Here is the third section:

```
blockSize: 2
```

Note that this is the final section and could have had a shorter length.

```
[getAlphabetsThisBlock] info: {
  "blockSize": 2,
  "numOfPasses": 3,
  "indexHexEncodedDataAtStartOfPass": 4,
  "prevHash": "711c1a58472281001f2bedcc93984c65eb7181328e556d6224264679fd5c270c"
}
[getAlphabetsThisBlock] passNum: 0, indexIntoBlock: 0
starting alphabet:
extended alphabet: 2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf
alphabetsThisBlock: [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf"
]
passNum: 0, indexIntoBlock: 1
starting alphabet:
extended alphabet: 512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370c
alphabetsThisBlock: [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370c"
]
passNum: 1, indexIntoBlock: 0
starting alphabet: 2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf
extended alphabet: 2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b2244436
alphabetsThisBlock: [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b2244436",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370c"
]
passNum: 1, indexIntoBlock: 1
starting alphabet: 512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370c
extended alphabet: 512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d6289149
alphabetsThisBlock: [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b2244436",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d6289149"
]
passNum: 2, indexIntoBlock: 0
starting alphabet: 2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b2244436
extended alphabet: 2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b22444362d1d7e6e4650472fb7877dc268563ccf0262d0beaa5d727325d77ac659e8798c
alphabetsThisBlock: [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b22444362d1d7e6e4650472fb7877dc268563ccf0262d0beaa5d727325d77ac659e8798c",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d6289149"
]
passNum: 2, indexIntoBlock: 1
starting alphabet: 512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d6289149
extended alphabet: 512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d628914969a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02
alphabetsThisBlock: [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b22444362d1d7e6e4650472fb7877dc268563ccf0262d0beaa5d727325d77ac659e8798c",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d628914969a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02"
]
initial alphabetsThisBlock (2): [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b22444362d1d7e6e4650472fb7877dc268563ccf0262d0beaa5d727325d77ac659e8798c",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d628914969a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02"
]
at this point, each alphabet is the same size (numOfPasses * hash size), but it's not guaranteed that each alphabet will contain the plaintext character.  so go through and extend any alphabets that do not yet contain the plaintext character
alphabetsThisBlock (length 2): [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b22444362d1d7e6e4650472fb7877dc268563ccf0262d0beaa5d727325d77ac659e8798c",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d628914969a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02"
]
alphabetsThisBlock (length 2): [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b22444362d1d7e6e4650472fb7877dc268563ccf0262d0beaa5d727325d77ac659e8798c",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d628914969a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02"
]
guaranteed alphabetsThisBlock (2): [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b22444362d1d7e6e4650472fb7877dc268563ccf0262d0beaa5d727325d77ac659e8798c",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d628914969a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02"
]
at this point, each alphabet is at least the minimum size and is guaranteed to have at least once instance of the plaintext hexChar.
return prevHash: 69a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02
[encryptFromHex_blockMode] alphabetsThisBlock: [
  "2941e321bf93d4c37cfcbb10cb1134686c835dc478c4a56ddc846806edb5cbdf2e7d955fffdc9cf3eb8e2baf3ebeec72fd88f68d8335744c891ce647b22444362d1d7e6e4650472fb7877dc268563ccf0262d0beaa5d727325d77ac659e8798c",
  "512f116cdcc98e519ccdaa8794e9b60206db8c21dbd09df6459bbc3a0401370cfcf2d5abfb1c7d63a12025b3b610476f3fcd1e1ea9d8299ca8187bb4d628914969a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02"
]
prevHash after alphabets created: 69a999ab4297894f3f64f84ab59b61748d9e9657de819cd926a2591e82805d02
encryptedIndexesThisBlock: 183,148
encryptedDataIndexes so far: 182,188,169,184,183,148
final resEncryptedData: 182,188,169,184,183,148
```

So there we have it. We went from our data, "foo", which is 3 characters in
length. Hex encoding turned this into 6 characters in length. We then, working
with 2-character sections, built up alphabets, each one being at least 3-hash
digest's in length. We then recorded the indices into those alphabets. All of
this worked at the hex level, none of it performed an XOR combining function.
It did not act strictly as a stream cipher, because we had to process multiple
characters' alphabets as a whole. Nor did it necessarily have to work as a
block, because there was a non-zero probability of needing to extend an
individual alphabet; also, the final section did not have to be padded.

At this point, the rest of the algorithm works the same as the stream version.

## attacks

There are always attacks available against encryption algorithms, but again, encrypt-gib
aims to leverage the assumption that cryptographic hashes are "effectively random".

### short-circuit (aka shortcut) brute force attacks

If used in stream mode (non-multipass block mode), encrypt-gib is susceptible to
short-circuit brute forcing, if the brute forcer knows the expected shape that
plaintext starts with, e.g. if it's a JSON object and starts with a `{`
character. In this case, the brute forcer only has to guess secrets against a
small subset of the initial ciphertext. Once a guess is deemed incorrect on the
small subset of ciphertext, they can move on to the next guess, avoiding
processing the ciphertext as a whole.

### multipass block mode short-circuit mitigation

In order to help mitigate against this, there is a `blockMode` parameter that
requires larger blocks of alphabets to be created before decryption (i.e.
dereferencing the index into a JIT alphabet), is possible even for the first
character. This should be used in combination with the `indexingMode` parameter
set to `lastIndexOf`, which will usually force multiple passes to be fully made
even for the very first character.

This works because each block section
is built up with some number of minimal number of passes that extend the
alphabets of each plaintext character in that section as a whole. So given
alphabets a0, a1, ..., an, where n is the character index into that section,
we will extend each alphabet as follows

```
Pass0[a0, a1, ..., an,], Pass1[a00, a11, ..., ann], ..., PassN[a0NNN, a1NNN, ..., anNNN]
```

So each section recursively hashes the `prevHash` from the previous character,
just as in the walkthrough above in the stream cipher mode. The difference is
that each alphabet is then automatically extended with other passes - **even if
those alphabets already contain the plaintext hex character to encipher**.

Any additional blocks are then concatenated with previous blocks
to produce the final encrypted text. Decryption happens the same way, as
alphabets are able to be reconstructed just as in the stream mode.

The multipass block mitigation technique creates a couple of dynamics:

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

## general notes

* ATOW Only UTF-8 data is supported.
* ATOW Nothing is overly optimized for runtime performance.
