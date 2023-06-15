# [ibGib](https://ibgib.space)

_i believe_

> overcoming division, hate, entropy with living, loving logic. the closed system does not exist.

in the world today, there is **so. much. opportunity.**

on the cusp of web3, quantum computing, agi, the metaverse and more, we as
technologists strive to make these goals a reality every single day. but to
_actually_ reach these goals , we **must** take a leap of faith beyond discrete
shannon information; beyond the idea of a complete, finite dataset; and beyond
the hubris of knowledge complete.

at the root of science is the ambition of **knowledge** but always married with
the recognition of **humility**. fundamentally **every** measurement has error;
**no knowledge** is set in stone; **every** conceptual framework in *every**
scientific discipline - no matter how seemingly powerful and innately "true" -
could itself be a local minimum, superseded by a more powerful, more robust
understanding.

> but this basic tenet of striving for perfection, over perfection achieved, stands in stark contrast with computer science's architectural approach to data.

each framework seeks a single source of truth; each one conflating fundamental
mathematical models based on proofs - a temporal misnomer - with truths. the
return of computer science to this acceptance, **this embrace of humility
expressed in our software architecture** will finally help us reach these goals
and move on to those we cannot yet even conceive.

ibgib is the metaverse foundation that embeds this humility _in code_. the word
itself, ibgib, is a dialectic composite that at its very core unites seemingly
contradicting pieces of information. it recognizes that each of our individual
experiences, while separate and siloed from each other are incomplete. _in
code_, ibgib elevates "belief" and "perspective" to first-class citizens, while
holding "knowledge" to account with the humility so core to science, but
currently so absent in computer science in practice.

# tl;dr

* ibgib
  * **genuinely innovative** dlt protocol to enable self-similar, metaversal computing
  * conceived and written over 20+ years and countless iterations for distributed computation
  * **uniquely both** cyclic **and** acyclic graph-based dlt _independently evolved from the bitcoin phenomenon_
  * prototype sans keystones: https://ibgib.space
    * slow and ugly to most, but hidden beauty for those who with eyes
    * prototype code (pre-breakout/refactor): https://github.com/wraiford/ibgib/tree/v0.2.729/ionic-gib
    * not a token, but would allow for defi domain implementations
* [encrypt-gib library](https://www.npmjs.com/package/@ibgib/encrypt-gib)
  * **genuinely innovative** hash-based encryption algorithm
    * isomorphic typescript implementation
  * cryptographic hashes as the only magical primitive
    * no, hashes are not just for signatures (quite the opposite)
  * unproven, but should be at least as post quantum resistant as the hash function
  * i'm offering up the rights to the algorithm in exchange for material investment into ibgib as a whole, see offer details.
* [keystone architecture](https://github.com/wraiford/ibgib/tree/master/keystone-gib)
  * **genuinely innovative** approach to distributed identity
  * dlt + sigma protocol-based zkp's
  * will interop with existing (pki + ca)-based domains (but will subsume them)
  * will interop with w3d's dids (but will subsume them)
  * will enable in-band/on-chain authn/z
  * will do all of this dry-ly wrt codebase for reduced surface area, increased integrity and durability

## offer

i am william raiford and i'm offering up front the short-term incentive of the
patent rights to my encrypt-gib algorithm, with the terms being expounded in the
next section.

i am offering this intrinsically as an important architectural piece of a future
which will include much more dlt-based metaversal collaboration (ibgib or no)
among humans and ai - both "big business" centralized models as today's
burgeoning llm's, in concert with their "small business" distributed, edge-based
cohorts.

i am also offering this extrinsically as one evidence of **genuine innovation**,
to differentiate myself from those who have unwittingly extruded their
distributed architecture from unscalable foundations.

i invite you to read about the [encrypt-gib
library](https://www.npmjs.com/package/@ibgib/encrypt-gib), and i encourage you
to cryptanalyze its viability, at least as a post quantum encryption candidate.
keep in mind, this is not optimized for size or speed efficiency, and i do not
proffer it as such. it's efficiency comes in **reduction of complexity** and
**increase in comprehensibility**. it is a novel low-magic algorithm, and though
it can be used today in situations where bandwidth and scale are not limiting
issues, it is intended to be used in ibgib's dlt architecture, specifically
yet-to-be-implemented [keystone
architecture](https://github.com/wraiford/ibgib/tree/master/keystone-gib), in
tandem with other existing cryptographic techniques. the details as to how it
fits in are too numerous to discuss here, however i do offer as, at the very
least, signal of validity, one existing patent that uses a hash-based, one-time
pad approach, the details of which are given below.

# why?

why commit resources to the ibgib project? well. what is the life of meaning?

> _collaboration_ is orchestration of _living information_ branching among _human spaces_.

> _distributed computation_ is orchestration of _living information_ across _artificial spaces_.

> _ibgib_ is orchestration of unified _living information_ among _both human and artificial_ participants.

at its heart, ibgib is a low-level, uniquely content-addressable dlt protocol
that genuinely differentiates itself by addressing this "life of meaning"
orchestration dry-ly **in code**. it does so by focusing on **timelines** of
beliefs held by participants in **spaces**. and this "space+time" approach is
not a gimmick from a sciency-sounding ad campaign. it is simply concise and
accurate.

it is impossible to summarize here just how impactful this approach can be. but
to start to grow eyes to see, first consider the current monopoly of
technological time: git.

git is already a language-agnostic dlt that enables occasionally connected
dynamics of merging timelines. it did not invent the version control jargon of
branching, forking (a special case of branching), or merging, but it did
implement these in a completely innovative way.

but these are also primitives that underlie database engines, which under the
hood, all record some version of a timeline log (usually monotonically
increasing) but with a key difference: databases fundamentally record events to
rehydrate the "single source of truth" to maximize integrity, **whereas git
fundamentally enables timeline dynamics both for rehydration and new timeline
creation**. ibgib's protocol similarly enables space+time dynamics for both
rehydration and creation, but in the general case.  to borrow still more from
einstein, ibgib is the general relativity to git's special relativity.

you see, git works at the text-based diff level, with a post hoc binary
mechanism to reduce bloat for practicality and its focused use case of source
control, with binary artifacts becoming more prevalent in codebases. but git's
implementation and hyper-focus for text-based optimization precludes it from
including its own metadata in its merkle dag. consequently, out-of-band metadata
is included in the .git folder. **you can copy git projects only via the
filesystem, never internally with just git itself. so now you are required to
maintain code for at least two systems (filesystem and git itself) for object
replication, authn/z, audit trails, yada yada yada, the list goes on.**

ibgib was designed as a "semantic version control", meaning diffs work at the
semantic level and conceivably can represent any transform from one discrete set
of content-addressable ibgib data to another. each transform itself is
content-addressed. each argument is content-addressed. each derivative is
content-addressed. the entire merkle graph contains **both the data and
metadata** used to create that data, **and all derivative data and metadata,
including e.g. identity.** this enables ibgib to send all data and metadata
using a dry, consistent mechanism but with various configurations, such as for
file replication, node orchestration, witness consensus, security requirement
negotiation, and plain old data communication (and still more). with ibgib,
we're abstracting the concept of a language-agnostic function and creating a
universally addressable functional programming paradigm.

> **this concept of data, metadata and derivative data living side by side is what enables ultimate scaleability in metaversal construction**.

when you send a chat message, you "git push > git merge" diffs from one
space+time into another space+time. since it is content-addressed, this produces
order-independent crdt behavior **for free** (the prototype uses this already).
because it is language-agnostic, living above implementation substrates, this
functional programming will enable "smart contracts" (a very limiting term)
**but without language lock-in**. since derivative data and metadata live
alongside origin data and metadata, this addressing system will enable cluster
configuration, file replication, consensus/witness orchestration...**re-using
the same dry, heavily tested code that is used when sending the chat message**.
when used in combination with my vision of the innovative keystone design, this
will enable truly mobile and distributed identity dynamics (human, ai,
corporate, etc.) required for true metaversal distributed computation.

i am not saying existing approaches won't achieve success -- projects like the
ipfs family, blockchain-based bitcoin's & ethereum's, w3c's rdf-based solid
project, the hyperledger project, roblox, meta, openai and more. far from it.
these are extremely motivated and ingenious people, and they will make it work
to an extent.

**i am** saying now that i'm finally ready to expand in multiple arenas, that
not materially investing in ibgib...
* given that i developed it in parallel to bitcoin;
* given that i was anticipating distributed edge-based ai participants from the get-go;
* given that i am, and have been, running alongside turing's train in my waterhousian fashion, driven by the use cases others do not see;
* and given the evidence of my novel hash-based encryption algorithm...

given all of these things, **i am** saying that not beginning to materially
invest in ibgib at this very moment in our own shared space+time would be a
~~Goddamn sin~~ mistake.

william

_(meta levity note: the Goddamn sin was just a little too melodramatic for me, but i enjoyed the strike-thru meta solution. i'm terrible with these kinds of serious documents. i have serious architectural opinions in a very small band of the wide world of cs, but i'm afraid i have always been terrible at writing papers. that's one of the reasons this engine would power an entirely new blogging system that combines thing like instagram, slack and more with a git-like openness.)_

# terms of offer for encrypt-gib encryption algorithm

i offer full ownership of the rights to the encrypt-gib encryption algorithm to
that **good party**, being defined as the one who adheres to these simple terms
in good faith, given that...

* the **good party** files for the patent itself first, which is to include the
  word "ibgib" for patent searchability & discoverability for other
  participants; and,
  * the **good party** pays all fees and meta fees for the patent filing.
* the **good party** makes material "investment" in the **ibgib dlt project**,
  in good faith, with the clear understanding that...
  * the term "investment" refers not only to capital investment, but of other
    resources available to the **good party**, including, but not limited to,
    both for-profit and not-for-profit business mechanics; and,
  * this investment is not a purchase of stock (as there is no company),
    controlling or otherwise, but rather is a gesture of good faith in our
    relationship going forward; and,
  * the investment begins to be reified no later than july 4, 2023; and,
  * this does not limit, in any fashion, others from investing (in the same
    general sense) either capital or other resources in the **ibgib dlt
    project** in any way going forward; and,
  * this does not limit, in any fashion, others from creating derivative
    businesses and/or products that relate to the **ibgib dlt project**.
* the **good party** allows royalty-free and unlimited usage of the
  encrypt-gib algorithm to any and all parties, when used in conjunction with
  the **ibgib dlt project**.
* in the case of the **bad party** filing for the patent, with the **bad party**
  comprising those participants who do not adhere to these simple terms, the
  **good party** will pay all fees and meta fees, e.g. legal fees, until the
  **good party** obtain the patent rights that rightly originated with myself
  and, via righteous fulfillment of this contract, transferred to the **good
  party**.

i make no guarantees to the patentability of the algorithm, except my good faith
guarantee that...

* i alone invented the encrypt-gib algorithm; and,
* i have done due diligence in researching existing algorithms, using the
  extremely limited financial resources available to me; and,
* i have come across only one existing result that uses a remotely similar
  algorithm that...
  * has patent details of: jan. 9, 1996, patent number u.s. pat. no. 5,483,598,
    kaufman and perlman, "message encryption using a hash function"; and,
  * is only similar (and as such is validation for encrypt-gib's approach) in
    that it uses recursive hashing for message encryption, creating an
    arbitrary-length 1-time pad which is indeed similar, but not equivalent to
    encrypt-gib's one-time just-in-time (jit) "alphabets",
  * has more conventional stream ciphering details for the actual enciphering
    phase that relies on a binary-level xor operation on the keystream, which
    is completely different from encrypt-gib's substitution cipher at the
    hex-level; in addition to...
    * encrypt-gib's generalization of the round function allows for
      parameterized recursive hashing, including but not limited to...
      * multiple modes of operation with respect to interaction with the salt
        within each round function iteration ("salt strategy"); and,
      * per use-case customization of recursions of hashing per round function
        iteration ("recursions per hash" parameter); and,
    * encrypt-gib's customizable block mode, which...
      * helps mitigate short-circuit brute force attempts by sectioning plaintext
        data processing in a way that also enables memory-hard processing; and,
    * other facets as well.
  * does **not**
    * operate at the hex level; nor,
    * utilize the 1-time pads as dynamically, but deterministically, composeable
      alphabets with jit extensions as needed for encoding via indices into
      those alphabets; nor,
    * create parameterized configurable sections to mitigate short-circuit
      brute force attacks; nor,
    * utilize parameterized configurable sections combined with the jit
      alphabet constructions to enable memory-hard encryption to mitigate against
      parallelizing attacks.

**i am offering no guarantees, implied or explicit. there is still much work to
be done. this contract is given entirely in, and acts entirely upon, good faith
with the good party. filing for the patent is acceptance of these plain-english
terms, and in general is meant to foster an environment amenable to the ibgib
dlt project, which itself is meant to enable, or to aid in enabling, the
metaversal platform here on earth. this platform seeks to create a balance of
human-based and artificially-based computation, to the profit of all. i
personally work on a donation-only basis. i believe in the future where those of
us who commit to working in the translucent and sovereign light, not just in
source code but with data and metadata as well, will continue to work on a
donation-only basis in order that we may continue to develop this earth, which
we have been given, and all other earths, in an ecologically friendly,
responsible and inclusive way.**

# ps

the following encryption examples are to be of use for the **good party**.

## simple encryption with known secrets

secret: 42

### [weaker encryption with known secret.42.encrypt-gib](./encryption-examples/weaker%20encryption%20with%20known%20secret.42.encrypt-gib)

```
{"encryptedData":"1,132,7,4,10,31,3,9,5,17,10,11,61,2,2,1,0,3,14,32,17,32,8,5,52,55,15,14,20,22,23,46,5,4,54,16,37,25,7,4,13,8,1,0,2,31,11,92,2,7,3,3,21,10,8,3,15,22,16,31,21,0,5,5,6,5,17,19,11,12,2,19,9,3,42,21,18,7,9,14,25,10,6,4,3,30,6,19,6,3","initialRecursions":1000,"recursionsPerHash":2,"salt":"6fdb86fda3e1e556cab02cfea9a64911fe051f9dcdd02ca4a27ca6ef4fa98129","saltStrategy":"initialAppend","hashAlgorithm":"SHA-256","encryptedDataDelimiter":","}
```

## simple encryption with known data

these encryptions all have the same data. the point is to show how the output
change given the same data - though note that even if the index is common among
ciphertexts, the corresponding alphabet will be different. so ultimately
fore-knowledge of the plaintext, even complete knowledge, should not help speed
up beyond brute force computation time. note the weaker parameter set used here
(stream mode, not block mode) does allow for short-circuiting brute force
attacks with fore-knowledge of the start of the plaintext.

data: What do you get if you multiply six by nine?

### [simple encryption with known data.weaker secret.weaker strength.encrypt-gib](./encryption-examples/simple%20encryption%20with%20known%20data.weaker%20secret.weaker%20strength.encrypt-gib)

```
{"encryptedData":"9,64,40,0,0,38,3,2,3,17,9,10,8,21,6,16,22,8,81,13,27,16,23,3,1,16,3,11,0,30,1,15,24,4,23,23,13,43,5,3,7,35,58,27,20,12,4,22,31,24,7,6,8,2,16,12,42,10,8,3,14,0,30,0,2,5,17,14,26,14,4,6,10,23,5,3,52,0,8,38,4,6,29,0,16,1,29,4","initialRecursions":1000,"recursionsPerHash":2,"salt":"5f8c52953285b101778fb782e00ddcf87ab360039bae4c90b39d2270c6ff6a3c","saltStrategy":"initialAppend","hashAlgorithm":"SHA-256","encryptedDataDelimiter":","}
```

### [simple encryption with known data.weaker secret.stronger strength.encrypt-gib](./encryption-examples/simple%20encryption%20with%20known%20data.weaker%20secret.stronger%20strength.encrypt-gib)

```
{"initialRecursions":30000,"salt":"d0672c5ea66e2374a963f48523f3e9116f4acd1b461fc0e2592ba0d19514e0fa","saltStrategy":"prependPerHash","hashAlgorithm":"SHA-512","indexingMode":"lastIndexOf","recursionsPerHash":10,"blockMode":{"maxBlockSize":1000,"numOfPasses":100},"encryptedData":"12795,12794,12782,12779,12789,12757,12799,12789,12789,12795,12763,12797,12760,12778,12793,12775,12797,12787,12795,12792,12788,12794,12799,12751,12795,12792,12749,12792,12790,12790,12799,12784,12785,12796,12793,12781,12791,12774,12781,12795,12721,12766,12796,12797,12784,12756,12782,12771,12788,12784,12791,12796,12788,12778,12790,12777,12795,12778,12797,12777,12787,12793,12793,12789,12777,12787,12784,12788,12791,12797,12777,12734,12789,12793,12794,12792,12779,12791,12799,12793,12774,12784,12790,12793,12793,12793,12788,12752"}
```

### [simple encryption with known data.stronger secret.weaker strength.encrypt-gib](./encryption-examples/simple%20encryption%20with%20known%20data.stronger%20secret.weaker%20strength.encrypt-gib)

```
{"encryptedData":"5,21,1,9,1,1,0,17,12,1,2,22,16,29,2,33,1,8,38,4,4,4,6,11,1,9,39,34,55,16,0,10,20,6,11,29,20,0,16,30,4,9,19,17,30,26,6,18,38,1,1,17,6,13,23,3,0,13,10,1,34,40,2,14,12,3,7,29,6,35,3,6,2,2,2,33,9,7,8,10,2,34,5,2,30,5,13,67","initialRecursions":1000,"recursionsPerHash":2,"salt":"20b68c32b49bb59ec5aab92660d3fb7dd3257ac592acd2a1ec8b124a181c9802","saltStrategy":"initialAppend","hashAlgorithm":"SHA-256","encryptedDataDelimiter":","}
```

### [simple encryption with known data.stronger secret.stronger strength.encrypt-gib](./encryption-examples/simple%20encryption%20with%20known%20data.stronger%20secret.stronger%20strength.encrypt-gib)

```
{"initialRecursions":30000,"salt":"19bf66cb80c929b077976318a428fcb57fdb5158aa67397416cd001e3fe3ac37","saltStrategy":"prependPerHash","hashAlgorithm":"SHA-512","indexingMode":"lastIndexOf","recursionsPerHash":10,"blockMode":{"maxBlockSize":1000,"numOfPasses":100},"encryptedData":"12723,12794,12794,12796,12799,12760,12796,12788,12776,12768,12794,12775,12798,12792,12778,12792,12768,12774,12748,12796,12784,12785,12798,12764,12795,12776,12778,12798,12793,12791,12798,12794,12789,12780,12793,12788,12793,12780,12786,12784,12726,12789,12797,12787,12788,12768,12778,12793,12768,12790,12781,12791,12797,12775,12744,12795,12795,12799,12799,12780,12785,12785,12786,12777,12792,12796,12748,12796,12765,12783,12788,12799,12798,12796,12786,12792,12777,12785,12761,12797,12763,12799,12774,12796,12797,12780,12796,12726"}
```

### [short message with much longer secret.stronger strength wat](./encryption-examples/wat.encrypt-gib)

silly really. could be fun cracking though...mildly diverting

## [gather - contact details](./encryption-examples/gather.encrypt-gib)

all are invited.
