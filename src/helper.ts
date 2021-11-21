import { HashAlgorithm } from './types';
var crypto = require('crypto');

export function clone(obj: any) {
    return JSON.parse(JSON.stringify(obj));
}

export function getTimestamp() {
    return (new Date()).toUTCString();
}

/**
 * Simple hash function.
 *
 * NOTE:
 *   This is not used for ibGib.gib values (ATOW)
 *   but rather as a helper function for generating random UUIDs.
 *
 * @param s string to hash
 * @param algorithm to use, currently only 'SHA-256'
 */
 export async function hash({
    s,
    algorithm = 'SHA-256',
}: {
    s: string,
    algorithm?: HashAlgorithm,
}): Promise<string> {
    if (!s) { return ''; }

    const validAlgorithms = Object.values(HashAlgorithm);
    if (!validAlgorithms.includes(algorithm)) {
        console.error(`Only ${validAlgorithms} implemented`); return '';
    }
    try {
        if (crypto) {
            if (crypto.subtle) {
                // browser I think
                const msgUint8 = new TextEncoder().encode(s);
                // const buffer = await crypto.subtle.digest('SHA-256', msgUint8);
                const buffer = await crypto.subtle.digest(algorithm, msgUint8);
                const asArray = Array.from(new Uint8Array(buffer));
                return asArray.map(b => b.toString(16).padStart(2, '0')).join('');
            } else if (crypto.createHash) {
                // node
                // let hash = crypto.createHash('sha256');
                let hash = crypto.createHash(algorithm.replace('-', '').toLowerCase());
                hash.update(s);
                return hash.digest('hex');
            } else {
                throw new Error('Cannot create hash, as unknown crypto library version.');
            }
        }
        else {
            throw new Error('Cannot create hash, crypto falsy.');
        }
    } catch (e) {
        console.error(e.message);
        return '';
    }
}

/**
 * Simple func to generate UUID (sha-256 hash basically).
 *
 * @param seedSize size of seed for UUID generation
 */
export async function getUUID(seedSize = 64): Promise<string> {
    let uuid: string = '';
    if (seedSize < 32) { throw new Error(`Seed size must be at least 32`); }
    if (!crypto) { throw new Error(`Cannot create UUID, as unknown crypto library version.`); }

    if (crypto.getRandomValues) {
        // browser crypto!
        let values = new Uint32Array(seedSize);
        crypto.getRandomValues(values);
        uuid = await hash({s: values.join('')});
    } else if (crypto.randomBytes) {
        const bytes = crypto.randomBytes(seedSize);
        uuid = await hash({s: bytes.toString('hex')});
    } else {
        if (!crypto) { throw new Error(`Cannot create UUID, as crypto is not falsy but unknown crypto library version.`); }
    }

    if (!uuid) { throw new Error(`Did not create UUID...hmm...`); }

    return uuid;
}

/**
 * Syntactic sugar for JSON.stringify(obj, null, 2);
 *
 * @param obj to pretty stringify
 */
export function pretty(obj: any): string {
    return JSON.stringify(obj, null, 2);
}

/**
 * Just delays given number of ms.
 *
 * @param ms milliseconds to delay
 */
export async function delay(ms: number): Promise<void> {
    return new Promise<void>(resolve => {
        setTimeout(() => {
            resolve();
        }, ms);
    });
}

// #region encodeStringToHexString, decodeHexStringToString related

// THANK YOU Stack Overflow,  Simon Buchan, and others at https://stackoverflow.com/questions/21647928/javascript-unicode-string-to-hex

/**
 * Convert some string to a string with only hex characters.
 *
 * Should (hopefully!) be reversible.
 *
 * @param s string to convert to hex string
 * @returns string that only contains hexidecimal characters (0-9, a-f)
 */
export function encodeStringToHexString(s: string): Promise<string> {
    const lc = `[${encodeStringToHexString.name}]`;
    return new Promise((resolve, reject) => {
        try {
            let bytes = stringToUTF8Bytes(s);
            let hexString = bytesToHexString(bytes);
            resolve(hexString);
        } catch (error) {
            console.error(`${lc} ${error.message}`);
            reject(error);
        }
    });
}

function stringToUTF8Bytes(s: string): Uint8Array {
    const lc = `[${stringToUTF8Bytes.name}]`;
    try {
        return new TextEncoder().encode(s);
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}

function bytesToHexString(bytes: Uint8Array): string {
    const lc = `[${bytesToHexString.name}]`;
    try {
        return Array.from(
            bytes,
            byte => byte.toString(16).padStart(2, '0')
        ).join("");
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}

/**
 * Decodes the hex-encoded string back to the original text.
 *
 * @param hexString Encoded x of some some data string
 * @returns Decoded (original hopefully!) text
 */
export function decodeHexStringToString(hexString: string): Promise<string> {
    const lc = `[${decodeHexStringToString.name}]`;
    return new Promise((resolve, reject) => {
        try {
            // console.log(`${lc} hexString (len: ${hexString.length}): ${hexString}`);
            const bytes = hexStringToBytes(hexString);
            const s = utf8BytesToString(bytes);
            resolve(s);
        } catch (error) {
            console.error(`${lc} ${error.message}`);
            reject(error);
        }
    });
}

/**
 * Converts hex to bytes.
 *
 * Ty also https://stackoverflow.com/questions/14603205/how-to-convert-hex-string-into-a-bytes-array-and-a-bytes-array-in-the-hex-strin
 *
 * @param hexString string that (obviously) should be hex to convert to bytes
 */
function hexStringToBytes(hexString: string): Uint8Array {
    const lc = `[${hexStringToBytes.name}]`;
    try {
        // console.log(`${lc} hexString (len: ${hexString.length}): ${hexString}`);
        if (hexString.length % 2 !== 0) { throw new Error(`invalid hex string. length %2 !== 0`); }
        const numBytes = hexString.length / 2;
        const bytes = new Uint8Array(numBytes);
        for (let i = 0; i < numBytes; i++) {
            bytes[i] = parseInt(hexString.substr(i*2, 2), 16);
        }
        return bytes;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}
function utf8BytesToString(bytes: Uint8Array): string {
    const lc = `[${utf8BytesToString.name}]`;
    try {
        return new TextDecoder().decode(bytes);
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    }
}

// #endregion
