import { PathOrFileDescriptor, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { encrypt, decrypt } from './crypto';

import jwt from 'jsonwebtoken';
import { verify } from './utils';

interface options {
    recursive?: boolean
    excludes?: String[]
}

export function decryptJWT(source: PathOrFileDescriptor, target: PathOrFileDescriptor | undefined = undefined) {
    if (verify()) {

        const dataKeys = join(process.cwd(), '.cqx', 'keys')
        const key = readFileSync(join(dataKeys, ".passiv.key")).toString()
        const dataCrypt = readFileSync(source).toString()
        const dataDcrypt = decrypt(dataCrypt, dataKeys)
        const dataJWT = jwt.verify(dataDcrypt, key)

        if (target !== undefined) {
            writeFileSync(target, String(dataJWT))
        } else {
            return dataJWT
        }
    }
}


export function encryptJWT(data: object, target: PathOrFileDescriptor | undefined = undefined) {
    if (verify()) {
        const dataKeys: PathOrFileDescriptor = join(process.cwd(), '.cqx', 'keys')
        const key: string = readFileSync(join(dataKeys, ".passiv.key")).toString()
        const dataJWT = jwt.sign(data, key)

        if (target !== undefined) {
            writeFileSync(target, encrypt(dataJWT, dataKeys))
        } else {
            return encrypt(dataJWT, dataKeys)
        }
    }
}

export function encryptObject(data: Object, options: options = { excludes: [], recursive: true }) {
    let excludes = options.excludes || []
    let recursive = options.recursive === false ? false : true

    let keys = Object.keys(data)

    keys.forEach(field => {
        if (!excludes.includes(field)) {
            if (data[field] instanceof Object) {
                if (recursive) {
                    data[field]=null
                    data[field] = encryptObject(data[field], options)
                }
            }
            else {              
                data[field] = encrypt(String(data[field]))
            }
        }
    });

    return data
}


export function decryptObject(data: Object, options: options = { excludes: [], recursive: true }) {

    let excludes = options?.excludes || []
    let recursive = options.recursive === false ? false : true

    let keys = Object.keys(data)

    keys.forEach(field => {
        if (!excludes.includes(field)) {
            if (data[field] instanceof Object) {
                if (recursive) {
                    data[field] = decryptObject(data[field], options)
                }
            } else {
                data[field] = decrypt(data[field])
            }
        }
    });

    return data

}