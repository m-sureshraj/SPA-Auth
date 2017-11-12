'use strict';
const mongoose = require('mongoose');
const User = mongoose.model('User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { validationResult, check } = require('express-validator/check');
const { matchedData } = require('express-validator/filter');

class AuthController {
    constructor() {
        this.signUp = this.signUp.bind(this);
        this.signIn = this.signIn.bind(this);
    }

    authValidation() {
        return [
            check('email').isEmail().withMessage('must be an a email').trim().normalizeEmail(),
            check('password').isLength({ min: 5, max: 20 })
        ];
    }

    async signUp(req, res) {
        // how to handle if already loged in user trying to send a request
        // to this route ????
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.mapped() });
        }

        const { email, password } = matchedData(req);
        const user = new User({ email, password });

        try {
            const doc = await user.save();
            return res.status(200).json({ token: this.generateJwtToken(doc) });
        } catch (err) {
            if (err.code === 11000) return res.status(422).json({ err: 'email already in use' });

            res.status(422).json({ err: err.errmsg });
        }
    }

    async signIn(req, res, next) {
        // how to handle if already loged in user trying to send a request
        // to this route ????
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.mapped() });
        }

        const { email, password } = matchedData(req);

        try {
            const user = await User.findOne({ email }).lean().exec();
            if (!user) return res.status(401).json({ errors: 'Invalid credentials' });

            // found the user compare password
            if (!this.comparePassword(password, user.password)) {
                return res.status(401).json({ errors: 'Invalid credentials' });
            }

            return res.status(200).json({ token: this.generateJwtToken(user) });
        } catch (err) {
            next(err);
        }
    }

    generateJwtToken(data) {
        const token = jwt.sign({
            id: data._id,
            email: data.email,
            issuer: 'spa_auth'
        }, process.env.SECRET_KEY);

        return token;
    }

    // we can create this `comparePassword` inside user model methods,
    // but in the findOne() method we chain lean() method as well, lean method
    // does not attach any mongoose helpers to the object it returs, So we don't
    // have any access to user.comparePassword if we create this method inside user model
    comparePassword(candidatePass, originalPass) {
        // for the lazy.. i used sync version of compare method, in real app
        // use async version
        return bcrypt.compareSync(candidatePass, originalPass);
    }

    verifyToken(req, res, next) {
        const authorizationTokenHeadr = req.header('Authorization');

        if (!authorizationTokenHeadr) return next();

        const token = authorizationTokenHeadr.replace(/^Bearer\s/i, '');

        jwt.verify(token, process.env.SECRET_KEY, (err, decodedToken) => {
            if (err) return res.status(401).json({ err: 'unauthorized' });

            req.isAuthenticated = true;
            return next();
        });
    }

    requireAuth(req, res, next) {
        if (!req.isAuthenticated) return res.status(401).json({ err: 'unauthorized' });

        next();
    }
}

module.exports = new AuthController();
