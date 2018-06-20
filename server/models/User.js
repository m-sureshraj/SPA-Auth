'use strict';
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    id: Schema.ObjectId,
    email: {
        type: String,
        lowercase: true,
        trim: true,
        unique: true,
        required: [true, 'Email is required field']
    },
    password: {
        type: String,
        required: [true, 'Password is required field']
    },
    githubId: {
        type: String,
        default: null
    }
});

UserSchema.pre('save', function(next) {
    const user = this;

    if (!user.isModified('password')) return next();

    // encrypt password
    const salt = bcrypt.genSaltSync(10);
    user.password = bcrypt.hashSync(user.password, salt);
    next();
});

module.exports = mongoose.model('User', UserSchema);
