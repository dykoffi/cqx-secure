const { existsSync } = require('fs');
const { createCipheriv, createDecipheriv } = require('crypto');
const { join } = require('path');
const { cwd } = require('process');
const chalk = require('chalk');

exports.verify = function () {
    if (existsSync(join(cwd(), '.cqx'))) return true
    else return false
}

exports.crypt = function (data, algorithm, passiv, iv) {
    let cipher = createCipheriv(algorithm, passiv, iv)
    let crypted = cipher.update(data, 'utf8', 'hex')
    crypted += cipher.final('hex');
    return crypted;
}

exports.dcrypt = function (data, algorithm, passiv, iv) {
    var decipher = createDecipheriv(algorithm, passiv, iv)
    var dec = decipher.update(data, 'hex', 'utf8')
    dec += decipher.final('utf8');
    return dec;
}

exports.logError = function (...message) { console.error(chalk.bold.red("Failed"), ":", ...message); }
exports.logSuccess = function (...message) { console.log(chalk.bold.green("Success"), ":", ...message); }
exports.logInfo = function (...message) { console.log(chalk.bold.blueBright("Info"), ":", ...message); }

exports.algo = "aes-256-ctr"