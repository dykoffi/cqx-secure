export function decryptJWT(source: string, target?: string | undefined): any;
export function encryptJWT(data: string, target?: string | undefined): string;
/**
 * A function that encrypt an object.
 * @function decryptObject
 * @param {object} data - Object you want to encrypt.
 * @param {{excludes: string[], recursive: boolean}} options - The folder which contains the keys.
 */
export function encryptObject(data: object, options?: {
    excludes: string[];
    recursive: boolean;
}): any;
/**
 * A function that decrypts an object.
 * @function decryptObject
 * @param {object} data - Object you want to decrypt.
 * @param {{excludes: string[], recursive: boolean}} options - The folder which contains the keys.
 */
export function decryptObject(data: object, options?: {
    excludes: string[];
    recursive: boolean;
}): any;
