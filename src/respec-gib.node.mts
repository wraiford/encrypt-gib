import { readdir, open } from 'node:fs/promises';
import { statSync } from 'node:fs';
import * as pathUtils from 'path';

import { pretty } from '@ibgib/helper-gib';
import { getGlobalRespecGib } from '@ibgib/helper-gib/dist/respec-gib/respec-gib.mjs';

// #region settings
const timerName = '[respec time to complete]';
console.time(timerName);
/**
 * This is how I enable/disable verbose logging. Do with it what you will.
 */
const logalot = false;

/** set this to the root of the respecs to look at */
const RESPEC_ROOT_DIR_RELATIVE_TO_BASE = './dist';

/** change this to suit your naming convention */
const RESPEC_FILE_REG_EXP = /^.+respec\.mjs$/;
// const RESPEC_FILE_REG_EXP = /^.*respec-gib.respec\.mjs$/; // example

/**
 * If on, will first load a file and see if there is an extra respecful
 * `respecfully`/`ifWe` block. Use these if you want to focus on a single or
 * subset of respecs.
 *
 * If there are no extra respecful blocks found in an entire file, that file
 * will be skipped.
 *
 * Note: this only is a flag to search through respec files.
 */
const LOOK_FOR_EXTRA_RESPEC = true;
/**
 * The names of the functions that indicate that we want to focus on just those
 * blocks.
 *
 * ATOW, for first run implementation here, I am implementing it such that it
 * will filter out files that don't have these indicators. The respec files that
 * do have these will execute fully, but the output will only include these
 * particular blocks.
 */
const EXTRA_RESPEC_FUNCTION_NAMES: string[] = ['respecfullyDear', 'ifWeMight'];

// #endregion settings

// #region 1. get respec paths

const basePath = process.cwd();
const srcPath = pathUtils.join(basePath, RESPEC_ROOT_DIR_RELATIVE_TO_BASE);

if (logalot) { console.log(`cwd: ${process.cwd()}`); }
if (logalot) { console.log(`basePath: ${basePath}`); }
if (logalot) { console.log(`srcPath: ${srcPath}`); }


const respecGib = getGlobalRespecGib();
const allRespecPaths = await getRespecFileFullPaths(srcPath, []);

if (logalot) { console.log(`allRespecPaths: ${allRespecPaths} (I: f5182a455375a8cf2aa6e1127a082423)`); }
let filteredRespecPaths: string[] | undefined = undefined;

if (LOOK_FOR_EXTRA_RESPEC) {
    const hasExtraRespecPromises = allRespecPaths.map(async respecPath => {
        const hasExtra = await respecFileHasExtraRespec(respecPath);
        return [respecPath, hasExtra] as [string, boolean];
    });
    const resPathHasExtraTuples = await Promise.all(hasExtraRespecPromises);
    filteredRespecPaths = resPathHasExtraTuples
        .filter(([_respecPath, hasExtra]) => hasExtra)
        .map(([respecPath, _hasExtra]) => respecPath);

    // if there are no files that have extra respec then we do all files
    if (filteredRespecPaths.length === 0) {
        if (logalot) { console.log(`filteredRespecPaths is empty. doing allRespecPaths found (I: b98f54656899646025eecb4c028ab523)`); }
        filteredRespecPaths = allRespecPaths.concat();
    } else {
        console.log(`filteredRespecPaths for extra respec: ${filteredRespecPaths} (I: b98f54656899646025eecb4c028ab523)`);
        respecGib.extraRespecOnly = true;
    }
}

// #endregion 1. get respec paths

respecGib.allRespecPaths = allRespecPaths;
respecGib.filteredRespecPaths = filteredRespecPaths;
const respecPaths = filteredRespecPaths ?? allRespecPaths;
respecGib.respecPaths = respecPaths;
if (logalot) { console.log(`respecPaths found:\n${respecPaths}`); }

// #region 2. execute paths' respective respecs

// for now, we'll do sequentially, but in the future we could conceivable farm
// these out to other node processes, or at least Promise.all

for (let i = 0; i < respecPaths.length; i++) {
    const respecPath = respecPaths[i];
    if (logalot) { console.log(respecPath); }
    const esm = await import(respecPath);
    if (logalot) { console.log(pretty(Object.keys(esm))); }
}

const skippedRespecPathCount = respecGib.allRespecPaths.length - respecGib.respecPaths.length;
if (skippedRespecPathCount > 0) {
    console.log('');
    console.error('\x1b[33m%s\x1b[0m', `${skippedRespecPathCount} respec files completely skipped.`);  // yellow
}
if (respecGib.ifWeBlocksSkipped > 0) {
    console.log('');
    console.error('\x1b[33m%s\x1b[0m', `${respecGib.ifWeBlocksSkipped} ifWe blocks ran but skipped reporting`);  // yellow
}

if (respecGib.errorMsgs.length === 0) {
    console.log('');
    console.error('\x1b[32m%s\x1b[0m', `💚💚 nothing but respec 💚💚`);  // green
} else {
    console.log('');
    console.error('\x1b[31m%s\x1b[0m', `💔💔 DISrespec found 💔💔`);  // red
    for (const errorMsg of respecGib.errorMsgs) {
        console.error('\x1b[31m%s\x1b[0m', errorMsg);  // red
    }
}

// #endregion 2. execute paths' respective respecs

// #region helper functions

/**
 * builds a list of respec file paths, recursively traversing subdirectories
 * starting from `dirPath`.
 *
 * @param dirPath a full path corresponding to a directory
 * @param found respec paths already found (used in recursive calls)
 * @returns list of all respec paths according to the respec regexp constant {@link RESPEC_FILE_REG_EXP}
 */
async function getRespecFileFullPaths(dirPath: string, found: string[]): Promise<string[]> {
    const lc = `[${getRespecFileFullPaths.name}][${dirPath}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 16026290523925f79ba1933847e2a623)`); }
        found ??= [];
        const children = await readdir(dirPath);
        if (logalot) { for (let i = 0; i < children.length; i++) { console.log(children[i]); } }
        const files: string[] = [];
        const dirs: string[] = [];
        children.forEach(name => {
            const fullPath = pathUtils.join(dirPath, name);
            const stat = statSync(fullPath);
            if (stat.isDirectory()) {
                // symbolic link could create a loop
                if (!stat.isSymbolicLink()) { dirs.push(fullPath); }
            } else if (!!name.match(RESPEC_FILE_REG_EXP)) {
                files.push(fullPath);
            }
        });

        found = found.concat(files);
        for (let i = 0; i < dirs.length; i++) {
            const subfound = await getRespecFileFullPaths(dirs[i], found);
            found = found.concat(subfound);
        }
        return Array.from(new Set(found)); // unique
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

/**
 * Searches through the file (without importing it) for extra respecful
 * functions.
 *
 * @param respecPath
 * @returns true if extra respecful functions found in file
 */
async function respecFileHasExtraRespec(respecPath: string): Promise<boolean> {
    const lc = `[${respecFileHasExtraRespec.name}]`;
    try {
        if (logalot) { console.log(`${lc} starting... (I: 61f3221917ba77175efa305b14defc23)`); }
        const file = await open(respecPath);
        for await (const line of file.readLines()) {
            const hasExtraRespecInLine =
                EXTRA_RESPEC_FUNCTION_NAMES.some(fnName => {
                    if (line.includes(`${fnName}(`)) { return true; }
                });
            if (hasExtraRespecInLine) {
                return true;
            }
        }
        return false;
    } catch (error) {
        console.error(`${lc} ${error.message}`);
        throw error;
    } finally {
        if (logalot) { console.log(`${lc} complete.`); }
    }
}

// #endregion helper functions

console.timeEnd(timerName);
