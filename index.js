const { existsSync, readFileSync, writeFileSync } = require('fs');
const { join } = require('path');

const { verify, crypt, dcrypt, algo, logError } = require('./libs/utils.js');
const { randomBytes } = require('crypto');

const jwt = require('jsonwebtoken');
const { cwd } = require('process');

const onFinished = require('on-finished');

const { PrismaClient } = require('@prisma/client')

const prisma = new PrismaClient()

/**
 * Crypt data 
 * @param {String} value 
 * @returns {String | null}
 */
exports.cryptG = function (value, folder = join(cwd(), '.cqx', 'keys')) {
    if (value !== null) {
        if (existsSync(join(folder, '.passiv.key')) && existsSync(join(folder, '.iv.key'))) {
            let passiv = readFileSync(join(folder, '.passiv.key')).toString()
            let iv = readFileSync(join(folder, '.iv.key')).toString()
            let Bpassiv = Buffer.from(passiv, 'base64')
            let Biv = Buffer.from(iv, 'base64')
            return crypt(value, algo, Bpassiv, Biv)
        } else {
            console.log('keys files not exist');
            return null
        }
    } else {
        return null
    }
}

/**
 * deCrypt data 
 * @param {String} value 
 * @returns {String | null}
 */
exports.dcryptG = function (value, folder = join(cwd(), '.cqx', 'keys')) {
    if (value !== null) {
        if (existsSync(join(folder, '.passiv.key')) && existsSync(join(folder, '.iv.key'))) {
            let passiv = readFileSync(join(folder, '.passiv.key')).toString()
            let iv = readFileSync(join(folder, '.iv.key')).toString()
            let Bpassiv = Buffer.from(passiv, 'base64')
            let Biv = Buffer.from(iv, 'base64')
            return dcrypt(value, algo, Bpassiv, Biv)
        } else {
            console.log('keys files not exist');
            return null
        }
    } else {
        return null
    }
}


/**
 * readCryptJson data 
 * @param {String} source 
 * @param {String} target 
 * @returns {String | null}
 */
exports.readCryptJson = function (source, target) {
    if (verify()) {
        const dataKeys = join(cwd(), '.cqx', 'keys')
        const key = readFileSync(join(dataKeys, ".pass")).toString()
        const dataCrypt = readFileSync(source).toString()
        const dataDcrypt = this.dcryptG(dataCrypt, dataKeys)
        const dataJWT = jwt.verify(dataDcrypt, key)

        if (target !== undefined) {
            writeFileSync(target, dataJWT)
        } else {
            return dataJWT
        }
    }
}

/**
 * writeCryptJson data 
 * @param {String} source 
 * @param {String} target 
 * @returns {String | null}
 */
exports.writeCryptJson = function (data, target) {
    if (verify()) {
        const dataKeys = join(cwd(), '.cqx', 'keys')
        const key = readFileSync(join(dataKeys, ".pass")).toString()
        const dataJWT = jwt.sign(data, key)
        writeFileSync(target, this.cryptG(dataJWT, dataKeys))
    }
}

/**
 * Crypt json object
 * @param {Object} object 
 * @param {Object} options 
 */
exports.cryptObject = function (object, options) {
    try {

        let excludes = options?.excludes || []
        let recursive = options?.recursive || false

        let keys = Object.keys(object)

        keys.forEach(field => {
            if (!excludes.includes(field)) {
                if (object[field] instanceof Object) {
                    if (recursive) {
                        object[field] = cryptObject(object[field], options)
                    }
                } else {
                    object[field] = cryptG(object[field])
                }
            }
        });

        return object

    } catch (error) {
        throw new Error(error)
    }

}

/**
 * Crypt json object
 * @param {Object} object 
 * @param {Object} options 
 */
exports.dcryptObject = function (object, options) {
    try {

        let excludes = options?.excludes || []
        let recursive = options?.recursive || false

        let keys = Object.keys(object)

        keys.forEach(field => {
            if (!excludes.includes(field)) {
                if (object[field] instanceof Object) {
                    if (recursive) {
                        object[field] = dcryptObject(object[field], options)
                    }
                } else {
                    object[field] = dcryptG(object[field])
                }
            }
        });

        return object

    } catch (error) {
        throw new Error(error)
    }

}


exports.giveToken = async function (data, permission = 'public', expiresIn = '24h') {
    try {
        data['_permission'] = permission
        let pass = randomBytes(32).toString('base64')
        let token = jwt.sign(data, pass, { expiresIn: expiresIn })

        await prisma.token_.create({ pass: this.cryptG(pass), value: this.cryptG(token) })

        return this.cryptG(token)

    } catch (error) { console.error(error); }
}

exports.checkToken = function (...permissions) {
    return async (req, res, next) => {
        try {
            let token = req.headers["x-access-token"]
            if (token) {
                let reply = await prisma.token_.findUnique({ where: { value: token } })
                token = dcryptG(token)
                if (reply === null) {
                    res.status(403).send({ error: "ErrorToken", message: "false token" })
                }
                else {
                    try {
                        let pass = dcryptG(reply.pass)
                        let data = jwt.verify(token, pass)
                        if (permissions) {
                            let userPermission = data['_permission']
                            if (permissions.includes(userPermission)) {
                                next()
                            } else {
                                res.status(403).send({ error: "ErrorPermission", message: "not authorized" })
                            }
                        } else {
                            next();
                        }
                    } catch (error) {
                        res.status(403).send({ error: "ErrorToken", message: error.message })
                    }
                }
            } else {
                res.status(403).send({ error: "ErrorToken", message: "Not token found" })
            }
        } catch (error) {
            res.status(403).send({ error: "ErrorPermission", message: "not authorized" })
            console.error(error.message);
        }
    };
}

exports.freeToken = async function (token) {
    try {
        await prisma.token_.delete({ where: { value: token } })
        return token
    } catch (error) { console.error(error); }
}

exports.saveLog = function () {
    return (req, res, next) => {
        res.header("x-powered-by", "cqx")
        onFinished(res, async () => {
            await prisma.log_.create(
                {
                    protocol: req.protocol,
                    method: req.method,
                    hostname: req.hostname,
                    path: req.originalUrl || req.url,
                    httpVersion: req.httpVersionMajor + '.' + req.httpVersionMinor,
                    statusCode: res.statusCode,
                    userIp: req.ip || req._remoteAddress || (req.connection && req.connection.remoteAddress),
                    userReferer: req.headers['referer'],
                    userAgent: req.headers['user-agent']
                }
            )
        })
        next()
    };
}

// Function wich serve API
exports.serve = function () {
    if (verify()) {
        const file = join(cwd(), '.cqx', 'data', '.release')
        const code = readFileSync(file).toString()
        eval(dcryptG(code))
    } else {
        logError("This not cqx project")
    }
}