/**
 * Crypt data
 * @param value
 */
export function cryptG(value: string, folder?: string): string | null;
/**
 * deCrypt data
 * @param value
 */
export function dcryptG(value: string, folder?: string): string | null;
/**
 * readCryptJson data
 * @param source
 * @param target
 */
export function readCryptJson(source: string, target: string): string | null;
/**
 * writeCryptJson data
 * @param data
 * @param target
 */
export function writeCryptJson(data: string, target: string): string | null;
/**
 * EnCrypt json object
 * @param object
 * @param options
 */
interface cryptObjectOptionsType {
    recursive: boolean,
    excludes: Array<string>
}

export function cryptObject(object: object, options: cryptObjectOptionsType): object;
/**
 * DeCrypt json object
 * @param object
 * @param options
 */
export function dcryptObject(object: object, options: cryptObjectOptionsType): object;

/**
 * Decrypt object in array
 * @param data 
 * @param options 
 */
export function dcryptArrayObject(data: string[], options: cryptObjectOptionsType): object;

/**
 * Encrypt object in array
 * @param data 
 * @param options 
 */
export function cryptArrayObject(data: string[], options: cryptObjectOptionsType): object;

/**
 * Generates token string, save it ib database and return it
 * @param data 
 * @param permission 
 * @param expiresIn 
 */
export function giveToken(data: object, permission?: string, expiresIn?: string): Promise<string>;

/**
 * Verify if token is valid
 * @param permissions 
 */
export function checkToken(...permissions: string[]): (req: any, res: any, next: any) => Promise<void>;

/**
 * Delete token
 * @param token 
 */
export function freeToken(token: string): Promise<any>;

/**
 * Save data request in database
 */
export function saveLog(): (req: any, res: any, next: any) => void;
