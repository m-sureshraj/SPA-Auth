'use strict';
const express = require('express');
const router = express.Router();
const authCtrl = require('../controllers/auth');
const blogCtrl = require('../controllers/blog/blogController');

router.use(authCtrl.verifyToken);

// manual signup
router.post('/signup', authCtrl.authValidation(), authCtrl.signUp);
router.post('/signin', authCtrl.authValidation(), authCtrl.signIn);

// signup via github
router.get('/auth/github', authCtrl.redirectToGithubAuth);
router.get('/auth/github/callback', authCtrl.handleGithubAuthentication);

// proteced routes
router.get('/protected', authCtrl.requireAuth, blogCtrl.getBlogs);

module.exports = router;
