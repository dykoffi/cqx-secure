const { decryptJWT, encryptJWT, encryptObject, decryptObject } = require("../libs/json.js")

describe("Test object functions", () => {

    describe("Test encryptJWT function", () => {

        let data = { nom: "koffi" }
        let cdata
        test("Must crypt data and return string", () => {
            cdata = encryptJWT(data, undefined)
            expect(cdata).toBeDefined()
        })

        test("Must crypt data and create file", () => {
            cdata = encryptJWT(data, "./tests/cdata")
        })

    })

    describe("Test decryptJWT function", () => {

        let ddata

        test("Must dcrypt data and return string", () => {
            ddata = decryptJWT("./tests/cdata", undefined)
            expect(ddata).toBeDefined()
        })

        test("Must dcrypt data and create file", () => {
            ddata = decryptJWT("./tests/cdata", "./tests/ddata.json")
        })

    })

    describe("Test encryptObject & decryptObject function", () => {

        let cdata
        let ddata

        let data = {
            firstName: "Edy",
            lastName: "KOFFI",
            school: {
                location: "Treichville",
                category: "High School",
                courses: ["Math", "English", "French"]
            }
        }

        test("Must encrypt object data with recursive option false", () => {
            cdata = encryptObject(data, { excludes: ["lastName"], recursive: false })
            expect(cdata["lastName"]).toBe("KOFFI")
            expect(cdata["school"]).toEqual({
                location: "Treichville",
                category: "High School",
                courses: ["Math", "English", "French"]
            })
        })

        test("Must encrypt object data without field excludes", () => {
            cdata = encryptObject(data)
            expect(cdata["school"]["category"]).toBe("5c5bd5ea6aa53490f7c6d5")
        })


        test("Must decrypt cdata to data object data without field category", () => {
            ddata = decryptObject(cdata)
            expect(ddata["school"]["location"]).toBe("Treichville")
        })

        test("Must decrypt object data with recursive option false", () => {

            ddata = decryptObject(cdata, { excludes: ["category"], recursive: false })
            expect(ddata["school"]["category"]).toBe("5c5bd5ea6aa53490f7c6d5")
        })
    })

})