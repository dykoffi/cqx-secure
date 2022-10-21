const { existsSync } = require("fs")
const { createCipheriv, createDecipheriv } = require("crypto")
const { join } = require("path")
const { cwd } = require("process")
const { bold } = require("chalk")

exports.verify = () => {
    if (existsSync(join(cwd(), '.cqx'))) return true
    else return false
}

exports.crypt = (data, algorithm, key, iv) => {
    let cipher = createCipheriv(algorithm, key, iv)
    let crypted = cipher.update(data, 'utf8', 'hex')
    return crypted;
}

exports.dcrypt = (data, algorithm, key, iv) => {
    var decipher = createDecipheriv(algorithm, key, iv)
    var dec = decipher.update(data, 'hex', 'utf8')
    return dec;
}

exports.logError = (...message) => { console.error(bold.red("Failed"), ":", ...message); }
exports.logSuccess = (...message) => { console.log(bold.green("Success"), ":", ...message); }
exports.logInfo = (...message) => { console.log(bold.blueBright("Info"), ":", ...message); }

exports.algo = "aes-256-gcm"