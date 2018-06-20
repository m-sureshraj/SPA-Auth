'use strict';
const mongoose = require('mongoose');
const User = mongoose.model('User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { validationResult, check } = require('express-validator/check');
const { matchedData } = require('express-validator/filter');
const axios = require('axios');

class AuthController {
    constructor() {
        this.signUp = this.signUp.bind(this);
        this.signIn = this.signIn.bind(this);
        this.redirectToGithubAuth = this.redirectToGithubAuth.bind(this);
        this.handleGithubAuthentication = this.handleGithubAuthentication.bind(this);
        this.github = {
            scope: ['user', 'user:email'],
            redirect_uri: `${process.env.WEB_URL}/auth/github/callback`,
            randomState: 'hello' // todo: generate random string
        };
    }

    authValidation() {
        return [
            check('email').isEmail()
                .withMessage('must be an a email')
                .trim()
                .normalizeEmail({
                    gmail_remove_dots: false,
                    gmail_convert_googlemaildotcom: false,
                    gmail_remove_subaddress: false
                }),
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

            // found the user now compare password
            if (!this.comparePassword(password, user.password)) {
                return res.status(401).json({ errors: 'Invalid credentials' });
            }

            return res.status(200).json({ token: this.generateJwtToken(user) });
        } catch (err) {
            next(err);
        }
    }

    generateJwtToken(data) {
        return jwt.sign({
            id: data._id,
            email: data.email,
            issuer: 'spa_auth'
        }, process.env.SECRET_KEY);
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
        const authorizationTokenHeader = req.header('Authorization');

        if (!authorizationTokenHeader) return next();

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

    redirectToGithubAuth(req, res) {
        const url = `https://github.com/login/oauth/authorize?` +
            `client_id=${process.env.GIT_CLIENT_ID}&` +
            `redirect_uri=${this.github.redirect_uri}&` +
            `scope=${this.github.scope.join(' ')}&` +
            `state=${this.github.randomState}`;

        return res.redirect(url);
    }

    async fetchAccessToken(req) {
        // todo: handle user not authorize the application
        const { code, state } = req.query;

        if (this.github.randomState !== state) {
            // cancel the flow
        }

        try {
            const accessTokenRes = await axios.post(
                'https://github.com/login/oauth/access_token',
                {
                    client_id: process.env.GIT_CLIENT_ID,
                    client_secret: process.env.GIT_CLIENT_SECRET,
                    redirect_uri: this.github.redirect_uri,
                    code,
                    state
                },
                { headers: { accept: 'application/json' } }
            );

            // todo: check the scope key from `accessTokenRes` whether users accepts
            // all the scopes we request
            return accessTokenRes.data.access_token;
        } catch (e) {
            // todo: handle error
        }
    }

    async fetchUserProfile(req) {
        try {
            const access_token = await this.fetchAccessToken(req);
            const userProfileRes = await axios.get(
                'https://api.github.com/user',
                { headers: { Authorization: `token ${access_token}` } }
            );

            if (!userProfileRes.data.email) {
                const { data: userEmailRes } = await axios.get(
                    'https://api.github.com/user/emails',
                    { headers: { Authorization: `token ${access_token}` } }
                );

                // filter primary email address
                userProfileRes.data.email = userEmailRes.filter(email => email.primary)[0]['email'];
            }

            return userProfileRes.data;
        } catch (e) {
            // todo: handle error
        }
    }

    async handleGithubAuthentication(req, res, next) {
        /* scenario 1: user has already account with that email
            * extract the email, id field from user profile
            * check whether user already exists with that email
            * if did no need to create new account for the user.
            * check the githubId field, if it is null update that
              field with extracted id
            * if it is not null no need to do anything
            * just generate new jwt token & return */

        /* scenario 2: user does not have a account yet
            * extract the email, id field from user profile
            * use id value for password field
            * create a new user account
            * generate new jwt token & return */

        try {
            let { id, email } = await this.fetchUserProfile(req);
            let user = await User.findOne({ email }).exec();
            id = id.toString(10);

            if (user) {
                if (!user.githubId) {
                    user.githubId = id;
                    user = await user.save();
                }

                return res.status(200).json({ token: this.generateJwtToken(user) });
            }

            // create new user account & return jwt token
            const newUser = new User({ email, password: id, githubId: id });
            const doc = await newUser.save();

            return res.status(200).json({ token: this.generateJwtToken(doc) });
        } catch (e) {
            // todo: handle error
            console.log(e);
        }
    }
}

module.exports = new AuthController();

// todo:
// * when generating jwt claim add xsrf_token key as well. for the value should be hashed
// * return generated jwt token via cookie (set HttpOnly property: js can't access the cookie)
// * return another cookie nameed 'XSRF-TOKEN' set already generate xsrf_token value here (don't
//   make httpOnly, because we need to read from js)
// * browser automatically attach cookie for each request, with that from the client side before
//   making any request read xsrf-token cookie and send it via custom header called `X-XSRF-TOKEN`
// * from the server side you extract the cookie from the request and compare it. as a second step
//   read the `X-XSRF-TOKEN` header and compare with jwt 'xsrf_token' key from the jwt claim
// * implement logout functionality

// https://stackoverflow.com/questions/2870371/why-is-jquerys-ajax-method-not-sending-my-session-cookie
// https://security.stackexchange.com/questions/115766/is-a-jwt-usable-as-a-csrf-token
// https://stackoverflow.com/questions/27067251/where-to-store-jwt-in-browser-how-to-protect-against-csrf
