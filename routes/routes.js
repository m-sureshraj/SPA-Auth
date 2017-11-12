'use strict';
const express = require('express');
const router = express.Router();
const authCtrl = require('../controllers/auth');
const blogCtrl = require('../controllers/blog/blogController');

router.use(authCtrl.verifyToken);

router.post('/signup', authCtrl.authValidation(), authCtrl.signUp);
router.post('/signin', authCtrl.authValidation(), authCtrl.signIn);
router.get('/protected', authCtrl.requireAuth, blogCtrl.getBlogs);

module.exports = router;
