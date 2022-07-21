import { encrypt, decrypt } from "../libs/crypto"

describe("Test crypto functions", () => {

    let data: string = "qwertyuiop"
    let cdata: string
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