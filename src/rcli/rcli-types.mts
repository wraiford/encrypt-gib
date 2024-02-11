
/**
 * Description of a parameter in an RCLI (Request/Command Line Interface) context.
 *
 * i think i have this ArgInfo already implemented elsewhere, and plugged up
 * with lex-gib helper, but i'm on a time crunch here. (Possibly thinking of
 * how I interpret robbot commands?)
 */
// export interface RCLIParamInfo {
//     /**
//      * default name of the param. RCLI will accept this in form of `--[name]="value"`.
//      * If it's a flag param, then this may just be `--[name]`
//      *
//      * @example for a param with name "output-path"
//      *
//      *     my-cmd --output-path="."
//      */
//     name: string;
//     // synonyms: string[]; // todo
//     /**
//      * If true, this param may not include a value, i.e., doesn't have `="somevalue"`.
//      *
//      * @example my-cmd --some-flag --non-flag="i am not a flag as i have an equals value"
//      */
//     isFlag?: boolean;
//     /**
//      * If true, then there could be multiple params in single RCLI request.
//      *
//      * @example ibgib --input="./file1.txt" --input="./file2.txt"
//      */
//     allowMultiple?: boolean;
//     /**
//      * The name of the interpretation of the arg (value).
//      */
//     argTypeName: RCLIArgTypeName;
// }

// /**
//  * Type that the RCLI (Request/Command Line Interface) arg should resolve to.
//  *
//  * @see {@link RCLIArgTypeName}
//  */
// export type RCLIArgType = string | number | boolean;

// /**
//  * String name of {@link RCLIArgType} that the RCLI (Request/Command Line Interface) arg should resolve to.
//  *
//  * This is used for runtime metadata and must correspond to
//  */
// export type RCLIArgTypeName = 'string' | 'integer' | 'boolean';

// /**
//  * Instance of a parameter in an RCLI (Request/Command Line Interface) context.
//  */
// export interface RCLIArgInfo<T extends RCLIArgType = string> extends RCLIParamInfo {
//     value?: T;
// }

/**
 * Parameter set for convenience when using the encrypt-gib RCLI.
 */
export type GenericEncryptionStrengthSetting = 'weaker' | 'stronger';
