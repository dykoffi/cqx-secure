/**
 * Crypt data
 * @param {String} value
 * @returns {String | null}
 */
export function cryptG(value: string, folder?: any): string | null;
/**
 * deCrypt data
 * @param {String} value
 * @returns {String | null}
 */
export function dcryptG(value: string, folder?: any): string | null;
/**
 * readCryptJson data
 * @param {String} source
 * @param {String} target
 * @returns {String | null}
 */
export function readCryptJson(source: string, target: string): string | null;
/**
 * writeCryptJson data
 * @param {String} source
 * @param {String} target
 * @returns {String | null}
 */
export function writeCryptJson(data: any, target: string): string | null;
/**
 * Crypt json object
 * @param {Object} object
 * @param {Object} options
 */
export function cryptObject(object: any, options: any): any;
/**
 * Crypt json object
 * @param {Object} object
 * @param {Object} options
 */
export function dcryptObject(object: any, options: any): any;
export function giveToken(data: any, permission?: string, expiresIn?: string): Promise<any>;
export function checkToken(...permissions: any[]): (req: any, res: any, next: any) => Promise<void>;
export function freeToken(token: any): Promise<any>;
export function saveLog(): (req: any, res: any, next: any) => void;
export function serve(): void;
