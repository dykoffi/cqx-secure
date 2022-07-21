
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { crypt, dcrypt, algo } from './utils';


export function encrypt(value: string, folder = join(process.cwd(), '.cqx', 'keys')): string {
    if (existsSync(join(folder, '.passiv.key')) && existsSync(join(folder, '.iv.key'))) {

        let passiv: string = readFileSync(join(folder, '.passiv.key')).toString()
        let iv: string = readFileSync(join(folder, '.iv.key')).toString()
        let Bpassiv: Buffer = Buffer.from(passiv, 'base64')
        let Biv: Buffer = Buffer.from(iv, 'base64')

        return crypt(value, algo, Bpassiv, Biv)

    } else {
        throw new Error("Keys not exist");
    }
}


export function decrypt(value: string, folder = join(process.cwd(), '.cqx', 'keys')): string {
    if (existsSync(join(folder, '.passiv.key')) && existsSync(join(folder, '.iv.key'))) {
        let passiv = readFileSync(join(folder, '.passiv.key')).toString()
        let iv = readFileSync(join(folder, '.iv.key')).toString()
        let Bpassiv = Buffer.from(passiv, 'base64')
        let Biv = Buffer.from(iv, 'base64')
        return dcrypt(value, algo, Bpassiv, Biv)
    } else {
        throw new Error("Keys not exist");
    }

}
