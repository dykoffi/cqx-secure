import { existsSync } from 'fs';
import { createCipheriv, createDecipheriv } from 'crypto';
import { join } from 'path';
import { cwd } from 'process';
import { bold } from 'chalk';

export function verify () {
    if (existsSync(join(cwd(), '.cqx'))) return true
    else return false
}

export function crypt (data, algorithm, passiv, iv) {
    let cipher = createCipheriv(algorithm, passiv, iv)
    let crypted = cipher.update(data, 'utf8', 'hex')
    crypted += cipher.final('hex');
    return crypted;
}

export function dcrypt (data, algorithm, passiv, iv) {
    var decipher = createDecipheriv(algorithm, passiv, iv)
    var dec = decipher.update(data, 'hex', 'utf8')
    dec += decipher.final('utf8');
    return dec;
}

export function logError(...message) { console.error(bold.red("Failed"), ":", ...message); }
export function logSuccess(...message) { console.log(bold.green("Success"), ":", ...message); }
export function logInfo(...message) { console.log(bold.blueBright("Info"), ":", ...message); }

export const algo = "aes-256-ctr"