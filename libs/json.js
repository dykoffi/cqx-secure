const { readFileSync, writeFileSync } = require("fs")
const { join } = require("path")
const { encrypt, decrypt } = require("./crypto")

const jwt = require("jsonwebtoken")
const { verify } = require("./utils")
const { cloneDeep } = require("lodash")

/* Decrypting the JWT. */
exports.decryptJWT = (source, target) => {
    if (verify()) {

        const dataKeys = join(process.cwd(), '.cqx', 'keys')
        const key = readFileSync(join(dataKeys, ".passiv.key")).toString()
        const dataCrypt = readFileSync(source).toString()
        const dataDcrypt = decrypt(dataCrypt, dataKeys)
        const dataJWT = jwt.verify(dataDcrypt, key)

        if (target !== undefined) {
            delete dataJWT['iat']
            writeFileSync(target, JSON.stringify(dataJWT, null, 2))
        } else {
            return dataJWT
        }
    }
}


/* Encrypting the data. */
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

/* Encrypting an object. */
function encryptObject (data, options = { excludes: [], recursive: true }) {

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


/* A function that decrypts an object. */
function decryptObject (data, options = { excludes: [], recursive: true }) {

    let excludes = options?.excludes || []
    let recursive = options.recursive === false ? false : true

    let cloneData = cloneDeep(data)

    let keys = Object.keys(cloneData)

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