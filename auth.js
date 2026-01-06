const crypto = require("crypto");

class JWTAuth {
    constructor(secret) {
        this.secret = secret;
    }

    generate(payload) {
        const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64");
        const body = Buffer.from(JSON.stringify(payload)).toString("base64");
        const signature = crypto
            .createHmac("sha256", this.secret)
            .update(header + "." + body)
            .digest("base64");

        return `${header}.${body}.${signature}`;
    }

    verify(token) {
        const [header, body, signature] = token.split(".");
        const expected = crypto
            .createHmac("sha256", this.secret)
            .update(header + "." + body)
            .digest("base64");

        return signature === expected;
    }
}

const auth = new JWTAuth("secret-key");
auth.generate({ user: "admin" });
