const { readFileSync, writeFileSync } = require("fs")
const { join } = require("path")
const { encrypt, decrypt } = require("./crypto")

const jwt = require("jsonwebtoken")
const { verify } = require("./utils")
const { cloneDeep } = require("lodash")

/**
 * Decrypt jtw data into file.
 * @function decryptJWT
 * @param {string} source - The path of the file you want to decrypt.
 * @param {string=} target - Optional - The path of the file which will contain the decrypted data.
 */

exports.decryptJWT = (source, target) => {
    if (verify()) {

        const dataKeys = join(process.cwd(), '.cqx', 'keys')
        const key = readFileSync(join(dataKeys, ".passiv.key")).toString()
        const dataCrypt = readFileSync(source).toString()
        const dataDcrypt = decrypt(dataCrypt, dataKeys)
        const dataJWT = jwt.verify(dataDcrypt, key)

        delete dataJWT['iat']

        if (target !== undefined) {
            writeFileSync(target, JSON.stringify(dataJWT, null, 2))
        } else {
            return dataJWT
        }
    }
}


/**
 * Encrypt jtw data into file.
 * @function encryptJWT
 * @param {string} data - The data you want to encrypt.
 * @param {string=} target - Optional - The path of the file which will contain the encrypted data.
 */

exports.encryptJWT = (data, target) => {
    if (verify()) {
        const dataKeys = join(process.cwd(), '.cqx', 'keys')
        const key = readFileSync(join(dataKeys, ".passiv.key")).toString()
        const dataJWT = jwt.sign(data, key)

        if (target !== undefined) {
            writeFileSync(target, encrypt(dataJWT, dataKeys))
        } else {
            return encrypt(dataJWT, dataKeys)
        }
    }
}


/**
 * A function that encrypt an object.
 * @function decryptObject
 * @param {object} data - Object you want to encrypt.
 * @param {{excludes: string[], recursive: boolean}} options - The folder which contains the keys.
 */

function encryptObject(data, options = { excludes: [], recursive: true }) {

    let excludes = options.excludes || []
    let recursive = options.recursive === false ? false : true

    let cloneData = cloneDeep(data)

    let keys = Object.keys(cloneData)

    keys.forEach(field => {
        if (!excludes.includes(field)) {
            if (cloneData[field] instanceof Object) {
                if (recursive) {
                    cloneData[field] = encryptObject(cloneData[field], options)
                }
            }
            else {
                cloneData[field] = encrypt(String(cloneData[field]))
            }
        }
    });

    return cloneData
}

/**
 * A function that decrypts an object.
 * @function decryptObject
 * @param {object} data - Object you want to decrypt.
 * @param {{excludes: string[], recursive: boolean}} options - The folder which contains the keys.
 */

function decryptObject(data, options = { excludes: [], recursive: true }) {

    let excludes = options?.excludes || []
    let recursive = options.recursive === false ? false : true

    let cloneData = cloneDeep(data)

    let keys = Object.keys(cloneData)

    /* Decrypting the data. */
    keys.forEach(field => {
        if (!excludes.includes(field)) {
            if (cloneData[field] instanceof Object) {
                if (recursive) {
                    cloneData[field] = decryptObject(cloneData[field], options)
                }
            } else {
                cloneData[field] = decrypt(String(cloneData[field]))
            }
        }
    });

    return cloneData

}

exports.encryptObject = encryptObject
exports.decryptObject = decryptObject