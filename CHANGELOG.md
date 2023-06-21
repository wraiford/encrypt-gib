# 0.2.20

* refactor: changed rli to use helper-gib `buildArgInfos` fn

# 0.2.19

* refactor: moved some rli code to helper-gib
  * updated helper-gib
* refactor: use helper-gib `extractErrorMsg` in catch blocks

# 0.2.18

* meta: readme

# 0.2.17

* refactor: multipass section to block
  * many various renames, including types, constants, variables,
    and file names/paths.
    * made backwards compatible fwiw
    * changed in readme and opportunity.
    * changed existing *.encrypt-gib
  * tested regression for gather.encrypt-gib again.
  * quick tests all pass. also, did quite awhile of stress test but
    ultimately need to do another full stress test.
  * also tweaked refactor for stream to stream-mode in paths.

# 0.2.16

* refactor: renamed temporary "legacy" name to "stream"
  * the original implementation does act as a stream cipher, even though
    it does not operate at a binary level. So "stream" seems to be more
    descriptive than "legacy".

# 0.2.15

* refactor: round function
  * I condensed each different implementation of the round function
    within encrypt and decrypt functions, both in legacy (stream) and
    multipass modes.
  * all tests passing for quick (not heavy stress tests yet though)
  * tested manually for regression also with gather.encrypt-gib and
    foo.encrypt-gib
  * adjusted README to reflect changes.
* meta: removed cruft
  * lots of cruft removal
  * did NOT remove unused logging, as those still are useful to uncomment
    * but dangerous if they get into production...
    * waffling on this a bit, but low priority since no one else uses this
      lib.
* meta: README warning
  * added a bolded warning at the top of the readme that describes the
    experimental nature of the lib.

# 0.2.14

* added multipass mode walkthrough section in the readme to contrast with
  the default cipher stream mode.
  * stubbed verbose logalot tracing throughout multipass mode for the
    walkthrough, but commented all out.
* request line interface (RLI) parameters added to expose more available
  parameters.
  * `initialRecursions`, `hashAlgorithm`, `saltSrategy`, etc.

# 0.2.0/1

* multipass mitigation against short-circuit brute force attacks.

# 0.1.7

* changed unit testing to use respec-gib inside helper-gib.

# 0.1.4/5

* changed npm package to scoped name @ibgib/encrypt-gib
* simplified isomorphic crypto
  * removed all aspects of `set_target.sh` hack
    * deleted .browser/.node src and tsconfigs
    * changed scripts in package.json
  * changed from mocha to jasmine
    * removed all aspects of mocha
    * added jasmine config for both node and browser
    * aligned package.json, tsconfigs, gitignore, npmignore files with other ibgib packages
      * currently reorg/refactoring ibgib packages

# 0.1.0

* changed `initialRecursions` to use 20000 default iterations.

# 0.0.6/7/8

* Added SHA-512 hashing.
  * Set default hashing to use this in `constants.ts`.

# 0.0.1

* Basic encrypt functionality

# notes

* this package is now isomorphic and the following note is no longer accurate. deprecated, so keeping the note here for now.
* ~~I'm publishing two versions of this lib at a time. **USUALLY** the odd number is the node version (because that is how I run `npm test`), and the higher even number is the browser target.~~
  * ~~Sometimes three build versions in a row will be the same to resynchronize.~~
    * ~~(I tried publishing node last, in case someone downloads and npm test doesn't run, but nobody is going to use this anyway so I'm going back to node odd, browser even)~~
