const { encrypt, decrypt } = require("../libs/crypto.js")

describe("Test crypto functions", () => {

    let data = "qwertyuiop"
    let cdata
    describe("Test encrypt function", () => {
        test("Must crypt data", () => {
            cdata = encrypt(data)
        })

        test("Must throw error not exist keys", () => {
            expect(() => encrypt(data, "./libs")).toThrow("Keys not exist")
        })
    })

    describe("Test dencrypt function", () => {
        test("Must dcrypt data", () => {
            expect(decrypt(cdata)).toBe(data)
        })

        test("Must throw error not exist keys", () => {
            expect(() => decrypt(cdata, "./libs")).toThrow("Keys not exist")
        })
    })
})