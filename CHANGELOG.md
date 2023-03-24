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

* I'm publishing two versions of this lib at a time. **USUALLY** the odd number is the
node version (because that is how I run `npm test`), and the higher even number is
the browser target.
  * Sometimes three build versions in a row will be the same to resynchronize.
    * (I tried publishing node last, in case someone downloads and npm test doesn't
      run, but nobody is going to use this anyway so I'm going back to node odd, browser even)
