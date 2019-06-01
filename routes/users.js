const errors = require('restify-errors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const auth = require('../utils/auth');
const config = require('../config');

module.exports = server => {

    // Register User
    server.post('/register', async (req,res,next) => {
        // Check for JSON
        if (!req.is('application/json')) {
            return next(new errors.InvalidContentError("Expects 'application/json'"));
        }
        const {email, password} = req.body;
        const user = new User({
            email,
            password
        });
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(user.password, salt, async (err, hash) => {
                // Hash Password
                user.password = hash;
                // Save User
                try {
                    const newUser = await user.save();
                    res.send(201);
                    next();
                } catch (err) {
                    return next( new errors.InternalError(err.message));
                }
            })
        })
    });

    // Auth user
    server.post('/auth', async (req, res, next) => {
        // Check for JSON
        if (!req.is('application/json')) {
            return next(new errors.InvalidContentError("Expects 'application/json'"));
        }
        const { email, password } = req.body;
        try {
            // Authenticate user
            const user = await auth.authenticate(email, password);
            // Create JWT (token)
            const token = jwt.sign(user.toJSON(), config.JWT_SECRET, {
                expiresIn: '5m'
            });
            const {  iat, exp } = jwt.decode(token);
            res.send({
                iat,
                exp,
                token
            })
            next();
        } catch (err) {
            // User unauthorized
            return next(new errors.UnauthorizedError(err));
        }
    })
}