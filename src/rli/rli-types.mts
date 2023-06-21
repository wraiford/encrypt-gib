
/**
 * Description of a parameter in an RLI (Request Line Interface) context.
 *
 * i think i have this ArgInfo already implemented elsewhere, and plugged up
 * with lex-gib helper, but i'm on a time crunch here. (Possibly thinking of
 * how I interpret robbot commands?)
 */
// export interface RLIParamInfo {
//     /**
//      * default name of the param. RLI will accept this in form of `--[name]="value"`.
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
//      * If true, then there could be multiple params in single RLI request.
//      *
//      * @example ibgib --input="./file1.txt" --input="./file2.txt"
//      */
//     allowMultiple?: boolean;
//     /**
//      * The name of the interpretation of the arg (value).
//      */
//     argTypeName: RLIArgTypeName;
// }

// /**
//  * Type that the RLI (Request Line Interface) arg should resolve to.
//  *
//  * @see {@link RLIArgTypeName}
//  */
// export type RLIArgType = string | number | boolean;

// /**
//  * String name of {@link RLIArgType} that the RLI (Request Line Interface) arg should resolve to.
//  *
//  * This is used for runtime metadata and must correspond to
//  */
// export type RLIArgTypeName = 'string' | 'integer' | 'boolean';

// /**
//  * Instance of a parameter in an RLI (Request Line Interface) context.
//  */
// export interface RLIArgInfo<T extends RLIArgType = string> extends RLIParamInfo {
//     value?: T;
// }

/**
 * Parameter set for convenience when using the encrypt-gib RLI.
 */
export type GenericEncryptionStrengthSetting = 'weaker' | 'stronger';
