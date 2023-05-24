import * as h from '@ibgib/helper-gib';

import { HashAlgorithm, SaltStrategy } from "../types.mjs";

/**
 * Builds the string that we will hash to get the next hash alphabet.
 *
 * @example
 * if we're prepending every hash, and this is the initial hash,
 * then we'll return `salt + secret`.
 *
 * @returns the string we're going to hash to get the next alphabet
 */
export function getPreHash({
    secret,
    prevHash,
    salt,
    saltStrategy,
}: {
    secret?: string,
    prevHash?: string,
    salt: string,
    saltStrategy: SaltStrategy,
}): string {
    if (!(prevHash || secret)) { throw new Error(`Either secret or prevHash is required, but both are falsy)`); }
    switch (saltStrategy) {
        case SaltStrategy.prependPerHash:
            return salt + (prevHash || secret)
        case SaltStrategy.appendPerHash:
            return (prevHash || secret) + salt;
        case SaltStrategy.initialPrepend:
            return prevHash ? prevHash : salt + secret;
        case SaltStrategy.initialAppend:
            return prevHash ? prevHash : secret + salt;
        default:
            throw new Error(`Unknown saltStrategy: ${saltStrategy}`);
    }
}

/**
 * Creates the first "alphabet" that we will index into.
 *
 * We have this separate, because the initialRecursions help us
 * chug on the secret.
 *
 * If the data's hex character is not in this alphabet, it will
 * be expanded just as any
 */
export async function doInitialRecursions({
    secret,
    initialRecursions,
    salt,
    saltStrategy,
    hashAlgorithm,
}: {
    secret: string,
    initialRecursions: number,
    salt: string,
    saltStrategy: SaltStrategy,
    hashAlgorithm: HashAlgorithm,
}): Promise<string> {
    const lc = `[${doInitialRecursions.name}]`;
    try {
        let hash: string | undefined;
        for (let i = 0; i < initialRecursions; i++) {
            const preHash = getPreHash({ secret, prevHash: hash, salt, saltStrategy });
            hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
        }
        if (!hash) { throw new Error(`hash was not created`); }
        return hash;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}
