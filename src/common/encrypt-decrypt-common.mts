import * as h from '@ibgib/helper-gib';
import { extractErrorMsg } from '@ibgib/helper-gib/dist/helpers/utils-helper.mjs';

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
    if (!(prevHash || secret)) { throw new Error(`Either secret or prevHash is required, but both are falsy (E: bee2849729ff410081d963777dcedb49))`); }
    // either prevHash or secret is guaranteed for all the following cases
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
            throw new Error(`Unknown saltStrategy: ${saltStrategy} (E: 235136af1a6c40eb9c17b2ca41c08a01)`);
    }
}

export async function execRound_getNextHash({
    secret,
    prevHash,
    count,
    salt,
    saltStrategy,
    hashAlgorithm,
}: {
    secret?: string,
    prevHash?: string,
    count: number,
    salt: string,
    saltStrategy: SaltStrategy,
    hashAlgorithm: HashAlgorithm,
}): Promise<string> {
    const lc = `[${execRound_getNextHash.name}]`;
    try {
        let hash = prevHash || undefined;
        for (let i = 0; i < count; i++) {
            const preHash = getPreHash({ secret, prevHash: hash, salt, saltStrategy });
            hash = await h.hash({ s: preHash, algorithm: hashAlgorithm });
        }
        if (!hash) { throw new Error(`hash was not created (E: 09dfdfd644734727a34a1bc0bd8e93b9)`); }
        return hash;
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
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
export async function doInitialRecursions_keystretch({
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
    const lc = `[${doInitialRecursions_keystretch.name}]`;
    try {
        const hash = await execRound_getNextHash({
            secret,
            count: initialRecursions,
            salt, saltStrategy, hashAlgorithm,
        })
        return hash;
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    }
}
