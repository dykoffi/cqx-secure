
const { existsSync, readFileSync } = require("fs")
const { join } = require("path")
const { crypt, dcrypt, algo } = require("./utils")

/**
 * Encrypt data with project keys.
 * @function encrypt
 * @param {string} value - The value you want to encrypt.
 * @param {string} folder - The folder which contains the keys.
 */

exports.encrypt = (value, folder = join(process.cwd(), '.cqx', 'keys')) => {
    if (existsSync(join(folder, '.passiv.key')) && existsSync(join(folder, '.iv.key'))) {

        let passiv = readFileSync(join(folder, '.passiv.key')).toString()
        let iv = readFileSync(join(folder, '.iv.key')).toString()
        let Bpassiv = Buffer.from(passiv, 'base64')
        let Biv = Buffer.from(iv, 'base64')

        return crypt(value, algo, Bpassiv, Biv)

    } else {
        throw new Error("Keys not exist");
    }
}

/**
 * Decrypt value with project keys.
 * @function decrypt
 * @param {string} value - The value you want to decrypt.
 * @param {string} folder - The folder which contains the keys.
 */

exports.decrypt = (value, folder = join(process.cwd(), '.cqx', 'keys')) => {
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
