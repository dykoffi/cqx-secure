import { PathOrFileDescriptor, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { encrypt, decrypt } from './crypto';

import jwt from 'jsonwebtoken';
import { verify } from './utils';
import { cloneDeep } from "lodash"

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
            delete dataJWT['iat']
            writeFileSync(target, JSON.stringify(dataJWT, null, 2))
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


export function decryptObject(data: Object, options: options = { excludes: [], recursive: true }) {

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