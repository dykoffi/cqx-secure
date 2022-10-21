const { readFileSync } = require("fs")
const { join } = require("path")
const { cwd } = require("process")
const { decrypt } = require("./crypto")
const { logError, verify } = require("./utils")

// Function wich serve API
module.exports = () => {
    if (verify()) {
        const file = join(cwd(), '.cqx', 'data', '.release')
        const code = readFileSync(file).toString()
        eval(decrypt(code))
    } else {
        logError("This not cqx project")
    }
}