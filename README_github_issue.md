I'm not a cryptographer, but I've studied it throughout my lifetime and am aware of some of the jargon of some existing encryption algorithms. I'm creating this issue to see if we can adjust the verbiage in the README.md to align with core concepts in that jargon. (Fundamentally, I have yet to find another present-day encryption algorithm that works at the high level in hex that I'm working with, as opposed to working at the binary level.)

_note: I am aware that not working at the binary level seems to be "inefficient". However the efficiency comes in reducing complexity to the point where the only primitive required beyond basic loops, concatenation, etc. is a hash function._

## key stretching

For example, I am aware that in code at [`doInitialRecursions`](https://github.com/wraiford/encrypt-gib/blob/main/src/encrypt-decrypt.ts#L536) (cruft removed for simplicity):

```typescript
for (let i = 0; i < initialRecursions; i++) {
    const preHash = getPreHash({secret, prevHash: hash, salt, saltStrategy});
    hash = await h.hash({s: preHash, algorithm: hashAlgorithm});
}
return hash;
```

Here, we are performing functionality similar to (precisely described in?) [key stretching](https://en.wikipedia.org/wiki/Key_stretching):

> There are several ways to perform key stretching. One way is to apply a [cryptographic hash function](https://en.wikipedia.org/wiki/Cryptographic_hash_function) or a [block cipher](https://en.wikipedia.org/wiki/Block_cipher) repeatedly in a loop.

In this case, I am recursively calling `hash` on the `preHash` driven by the parameters.

## hex encoding plaintext --> ?

There is an initial step that encodes the original plaintext data into hex in order to prepare for the function rounding. What is the term for this data massaging/preparation?

## key schedule, substitution and/or product cipher?

Here is a snapshot of the current heart of the encrypt algorithm (again cruft removed):

```typescript
// we have our prevHash starting point, so now we can iterate through the data
let encryptedDataIndexes = [];
for (let i = 0; i < hexEncodedData.length; i++) {
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
    encryptedDataIndexes.push(charIndex);
}

const encryptedData = encryptedDataIndexes.join(encryptedDataDelimiter);
```

This definitely seems to correspond to a [key schedule](https://en.wikipedia.org/wiki/Key_schedule) managing function rounds:

> In [cryptography](https://en.wikipedia.org/wiki/Cryptography), the so-called [product ciphers](https://en.wikipedia.org/wiki/Product_cipher) are a certain kind of cipher, where the (de-)ciphering of data is typically done as an iteration of rounds. The setup for each round is generally the same, except for round-specific fixed values called a round constant, and round-specific data derived from the [cipher key](https://en.wikipedia.org/wiki/Key_(cryptography)) called a round key. A key schedule is an algorithm that calculates all the round keys from the key.

It doesn't seem to be a conventional [substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher) because the encrypt-gib "alphabet" (existing README term which does already correspond to jargon) is produced/extended just-in-time per hex-encoded plaintext character. This JIT style seems to be more in line with [keystreams](https://en.wikipedia.org/wiki/Keystream), but our indexing into the JIT alphabet is definitely substituting an index as opposed to "combining' with the alphabet.

_note: Similarity mentioned between polyalphabetic and stream ciphers: "Modern [stream ciphers](https://en.wikipedia.org/wiki/Stream_cipher) can also be seen, from a sufficiently abstract perspective, to be a form of polyalphabetic cipher in which all the effort has gone into making the [keystream](https://en.wikipedia.org/wiki/Keystream) as long and unpredictable as possible."_


### substitution ciphers it is NOT

Here's a list of negatives for us:

* Simple
  * It is not a mixed/deranged alphabet, rather it is a JIT generated alphabet, or individual alphabets per round, depending on how you look at it.
  * It does not fall to the cryptanalysis due to frequency,
    * Well, it is strongly related (correlated?) to the (pseudo) randomness of the cryptographic hash function.
* Nomenclator, homophonic
  * Not very much like these, other than we are creating a "very large" alphabet.
* Polyalphabetic
  * Closer to us with "multiple" alphabets, but...
    * alphabet is not pre-chosen
    * alphabet is entirely unique to/generated by the secret (and usually salt, if using salt-per-hash strategy)
      * (even if there is a collision in hashes, it would only be for a single round, as the secret is then applied to the subsequent round and not just the previous hash)
  * [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) is getting closer...
    * ...the alphabet is chosen dynamically related to the secret per plaintext character, but...
      * The alphabets are finite/repeated...
        * whereas each encrypt-gib alphabet (if thinking of them singly) is unique relative to each other
          * (though obviously repeated at the size of the hash information < size of universe)
      * The alphabets are chosen naively for today's standards...
        * whereas each encrypt-gib alphabet is generated on a more complex prior, involving rounds of secret + salt + `prevHash`.
  * Beaufort, Gronsfeld
    * Not much different, except it does mention the Gronsfeld is self-inverse for decryption. Encrypt-gib reproduces the same alphabet(s) when decrypting as well.
  * autokey
    * Interrelates the message/plaintext with the key deterministically, but...
      * ...this is not necessary as use of cryptographic hashes already is intended to maximize pseudorandomness.
      * ...there are improvements that in general can be driven off of the plaintext and "intermingled" (appended) to the data and enciphered alongside original plaintext.
  * running key
    * Not really related, except in that it extends key length.
* Polygraphic
  * Currently encrypt-gib is only _slightly_ "polygraphic", in that when it encodes to hex at the start, which maps non-hex characters to multiple hex characters.
* One-time pad
  * This is very closely related to encrypt-gib, as alphabet(s) are considered unique to the parameters + secret.
  * > "typically, the plaintext letter is combined (not substituted) in some manner (e.g., [XOR](https://en.wikipedia.org/wiki/XOR)) with the key material character at that position."
    * In our case, the plaintext hex is not really substituted or combined in the historical senses, but rather its index into the "one-time" alphabet recorded.
  *  > "it requires that the key material be as long as the plaintext, actually [random](https://en.wikipedia.org/wiki/Random), used once and only once, and kept entirely secret from all except the sender and intended receiver."
    * encrypt-gib "key material" is artificially extended arbitrarily via the cryptographic hashing, much like cipher streams.
    * "random" has been the focused goal of many cryptographic hash functions,
      * per [MIT lecture notes](https://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-046j-design-and-analysis-of-algorithms-spring-2015/lecture-notes/MIT6_046JS15_lec21.pdf): "There are many desirable properties of a hash function... 4. Pseudo-random: The function behaves indistinguishable from a random oracle."
    * > "used once and only once"...
      * Actually how this is intended to be used with keystones, but beyond scope of this.
    * > "kept entirely secret"...
      * No, we're going with [Kerckhoffs' principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle) variant: only the secret is secret.

## conclusions

That's enough for now. Overall, it still does not seem to fit into the "substitution cipher" category, but it appears that there are some abstract grey areas acknowledged on Wikipedia, which shouldn't be too surprising.

I've gone through block and stream ciphers previously, but perhaps I'll do more on those here as this was pretty fruitful. And then we can get the README updated.