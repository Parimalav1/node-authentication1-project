const express = require("express");
const knex = require("knex");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const server = express();

const usersRouter = require("./users/user-router.js");
const authRouter = require("./auth/auth-router.js");
const dbConnection = require("./connection.js");
const ornateLock = require("./auth/ornateLock-mw.js");

// creating a session, produce a cookie and send it to client
const sessionConfiguration = {
    name: "school",
    secret: "keep it secret, keep it safe!",
    cookie: {
        maxAge: 1000 * 60 * 5, // after 5 mins the cookie expires
        secure: process.env.COOKIE_SECURE || false, // if true cookie is only sent over https
        httpOnly: true, // JS cannot touch this cookie
    },
    resave: false,
    saveUninitialized: true, // GDPR Compliance, the client should drive this
    store: new KnexSessionStore({
        knex: dbConnection,
        tablename: "sessions",
        sidfieldname: "sid",
        createtable: true,
        clearInterval: 1000 * 60 * 60, // delete expired sessions every hour
    }),
};

server.use(express.json());
server.use(helmet());
server.use(cors());
server.use(session(sessionConfiguration));

server.use("/api/users", ornateLock, usersRouter);
server.use("/api/auth", authRouter);

server.get("/", (req, res) => {
    res.json({ api: "up" });
});

// hashing the password
server.get('/hash', (req, res) => {
    try {
        const password = req.headers.password;
        const rounds = process.env.HASH_ROUNDS || 6;
        const hash = bcrypt.hash(password, rounds);

        res.status(200).json({ password, hash });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
