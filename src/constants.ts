import { HashAlgorithm, SaltStrategy } from ".";

export var DEFAULT_SALT_STRATEGY: SaltStrategy = SaltStrategy.appendPerHash;
// export var DEFAULT_HASH_ALGORITHM: HashAlgorithm = 'SHA-256';
export var DEFAULT_HASH_ALGORITHM: HashAlgorithm = 'SHA-512';
export var DEFAULT_GETUUID_SEEDSIZE: number = 1024;
export var DEFAULT_INITIAL_RECURSIONS: number = 1024;
export var DEFAULT_RECURSIONS_PER_HASH: number = 1;

export var DEFAULT_ENCRYPTED_DATA_DELIMITER: string = ',';