import { randomBytes } from 'crypto';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { cryptG, dcryptG } from './crypto';

const prisma = new PrismaClient()

export async function giveToken(data, permission = 'public', expiresIn = '24h') {
    try {
        let data2 = { ...data, permission_: permission }
        let pass = randomBytes(32).toString('base64')
        let token = jwt.sign(data2, pass, { expiresIn: expiresIn })

        await prisma.token_.create({ data: { pass: cryptG(pass), value: cryptG(token) } })

        return cryptG(token)

    } catch (error) { console.error(error); }
}

export function checkToken(...permissions) {
    return async (req, res, next) => {
        try {
            permissions = permissions.length === 0 ? ["public"] : permissions
            let token = req.headers["x-access-token"]
            if (token) {
                let reply = await prisma.token_.findFirst({ where: { value: token } })
                if (reply === null) {
                    res.status(403).send({ error: "ErrorToken", message: "false token" })
                }
                else {
                    try {
                        token = dcryptG(token)
                        let pass = dcryptG(reply.pass)
                        let data = jwt.verify(token, pass)
                        if (permissions) {
                            let userPermission = data['permission_']
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

export async function freeToken(token) {
    try {
        await prisma.token_.delete({ where: { value: token } })
        return token
    } catch (error) { console.error(error); }
}
