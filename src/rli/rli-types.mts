
/**
 * i think i have this ArgInfo already implemented elsewhere, and plugged up
 * with lex-gib helper, but i'm on a time crunch here.
 */
export interface ArgInfo {
    name: string;
    // synonyms: string[]; // todo
    isFlag: boolean;
    value?: string | number | boolean;
}


export type GenericEncryptionStrengthSetting = 'weaker' | 'stronger';
