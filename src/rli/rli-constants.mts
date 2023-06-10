import { ArgInfo } from "./rli-types.mjs";

export const ENCRYPTED_OUTPUT_FILE_EXT = 'encrypt-gib';

export const ARG_INFO_HELP: ArgInfo = {
    name: 'help',
    isFlag: true,
}
export const ARG_INFO_ENCRYPT: ArgInfo = {
    name: 'encrypt',
    isFlag: false,
}
export const ARG_INFO_DECRYPT: ArgInfo = {
    name: 'decrypt',
    isFlag: false,
}
export const ARG_INFO_DATA_PATH: ArgInfo = {
    name: 'data-path',
    isFlag: false,
}
export const ARG_INFO_OUTPUT_PATH: ArgInfo = {
    name: 'output-path',
    isFlag: false,
}
export const ARG_INFO_DATA_STRING: ArgInfo = {
    name: 'data-string',
    isFlag: false,
}
export const ARG_INFO_STRENGTH: ArgInfo = {
    name: 'strength',
    isFlag: false,
}
export const ARG_INFO_SALT: ArgInfo = {
    name: 'salt',
    isFlag: false,
}

export const ARG_INFOS: ArgInfo[] = [
    ARG_INFO_HELP,
    ARG_INFO_ENCRYPT,
    ARG_INFO_DECRYPT,
    ARG_INFO_DATA_PATH,
    ARG_INFO_OUTPUT_PATH,
    ARG_INFO_DATA_STRING,
    ARG_INFO_STRENGTH,
    ARG_INFO_SALT,
];
