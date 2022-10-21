
const {decryptJWT, decryptObject, encryptJWT, encryptObject} = require("./libs/json")
const serve = require("./libs/serve")
const {decrypt, encrypt} = require("./libs/crypto")

exports.decrypt = decrypt
exports.encrypt = encrypt
exports.serve = serve
exports.decryptJWT = decryptJWT
exports.decryptObject = decryptObject
exports.encryptJWT = encryptJWT
exports.encryptObject = encryptObject