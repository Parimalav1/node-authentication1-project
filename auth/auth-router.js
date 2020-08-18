// Authentication is the process by which our Web API verifies the identity of a client that is trying to access a resource. 
// This is different from authorization, which comes after authentication and determines what type of access, if any, that a user should have.

// Adding authentication to a Web API requires that an API can:

// register user accounts.
// login to prove identity.
// logout of the system to invalidate the user’s access until they login again.
// add a way for users to reset their passwords.
// Proper authentication is difficult. 
// Some of the things we need to take into account when implementing authentication are:

// Password storage.
// Password strength.
// Brute-force safeguards.

const router = require("express").Router();
const bcrypt = require("bcryptjs");

const Users = require("../users/user-model.js");
const session = require("express-session");

// registering and syncing with hashed password
router.post("/register", (req, res) => {
    const { username, password } = req.body;
    // validate the user credentials, check password length, make sure it's alphanumeric, etc.
    // look at https://www.npmjs.com/package/joi for validation, also look at https://www.npmjs.com/package/express-validator
    const rounds = process.env.HASH_ROUNDS || 6;
    const hash = bcrypt.hashSync(password, rounds);
    return Users.add({ username, password: hash })
        .then(user => {
            res.status(201).json({ data: user });
        })
        .catch(err => res.json({ error: err.message }));
});

// validating the user and the session with session Id when logging in
router.post("/login", (req, res) => {
    let { username, password } = req.body;

    Users.findBy({ username })
        .then(([user]) => {
            if (user && bcrypt.compareSync(password, user.password)) {
                // user exists and password is good
                req.session.loggegIn = true;
                // if the session is active & in use by user
                res.status(201).json({
                    hello: user.username,
                    session: req.session,
                });
            } else {
                res.status(401).json({ error: "you shall not pass!" });
            }
        })
        .catch(err => {
            res.status(500).json({ error: err.message });
        });
});

router.get("/logout", (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (error) {
                res.status(500).json({
                    error: "could not log you out, please try later",
                });
            } else {
                res.status(204).end();
            }
        })
        // if (!error) {
        //     res.status(200).json({ msg: 'You can log out' }) or
        //     res.status(204).end();
        // } else {
        //     res.status(500).json({
        //         error: "could not log you out, please try later",
        //     }
    } else {
            res.status(200).json({ message: "already logged out" });
        }
    });

module.exports = router;
