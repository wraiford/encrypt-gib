/**
 * @module helper utility functions specific to encrypt-gib
 *
 * THANK YOU Stack Overflow, Simon Buchan, and others at https://stackoverflow.com/questions/21647928/javascript-unicode-string-to-hex
 */

import { extractErrorMsg } from "@ibgib/helper-gib/dist/helpers/utils-helper.mjs";


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
            console.error(`${lc} ${extractErrorMsg(error)}`);
            reject(error);
        }
    });
}

function stringToUTF8Bytes(s: string): Uint8Array {
    const lc = `[${stringToUTF8Bytes.name}]`;
    try {
        return new TextEncoder().encode(s);
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
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
        console.error(`${lc} ${extractErrorMsg(error)}`);
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
            console.error(`${lc} ${extractErrorMsg(error)}`);
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
            bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
        }
        return bytes;
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    }
}
function utf8BytesToString(bytes: Uint8Array): string {
    const lc = `[${utf8BytesToString.name}]`;
    try {
        return new TextDecoder().decode(bytes);
    } catch (error) {
        console.error(`${lc} ${extractErrorMsg(error)}`);
        throw error;
    }
}
