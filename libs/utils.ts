import { existsSync } from 'fs';
import { createCipheriv, createDecipheriv, CipherGCMTypes, CipherKey, BinaryLike } from 'crypto';
import { join } from 'path';
import { cwd } from 'process';
import { bold } from 'chalk';

export function verify(): boolean {
    if (existsSync(join(cwd(), '.cqx'))) return true
    else return false
}

export function crypt(data: string, algorithm: CipherGCMTypes, key: CipherKey, iv: BinaryLike): string {
    let cipher = createCipheriv(algorithm, key, iv)
    let crypted = cipher.update(data, 'utf8', 'hex')
    return crypted;
}

export function dcrypt(data: string, algorithm: CipherGCMTypes, key: CipherKey, iv: BinaryLike): string {
    var decipher = createDecipheriv(algorithm, key, iv)
    var dec = decipher.update(data, 'hex', 'utf8')
    return dec;
}

export function logError(...message: string[]): void { console.error(bold.red("Failed"), ":", ...message); }
export function logSuccess(...message: string[]): void { console.log(bold.green("Success"), ":", ...message); }
export function logInfo(...message: string[]): void { console.log(bold.blueBright("Info"), ":", ...message); }

export const algo: CipherGCMTypes = "aes-256-gcm"