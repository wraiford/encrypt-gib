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
