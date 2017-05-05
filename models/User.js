const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const secret = require('../config').secret;

const UserSchema = new mongoose.Schema({
    username: {
        type: String, 
        lowercase: true, 
        required: [true, "can't be blank"], 
        unique: true,
        match: [/^[a-zA-Z0-9]+$/, 'is invalid'], 
        index: true
    },
    email: {
        type: String, 
        lowercase: true, 
        required: [true, "can't be blank"], 
        unique: true,
        match: [/\S+@\S+\.\S+/, 'is invalid'],
        index: true //create index to optimize queries
    },
    bio: 'String',
    image: 'String',
    hash: 'String',
    salt: 'String'
},{
    timestamps: true
});

UserSchema.plugin(uniqueValidator, { message: 'is already taken' })

UserSchema.methods.setPassword = (password) => {
    this.salt = crypto.randomBytes(16).toString('hex');
    this.hash = crypto.pbkdf2Sync(pasword, this.salt, 1000, 512, 'sha512').toString('hex');
}

UserSchema.methods.validPassword = (password) => {
    let hash = crypto.pbkdf2Sync(password, this.salt, 1000, 521, 'sha512').toString('hex');
    return this.hash === hash
}

UserSchema.methods.generateJWT = () => {
  const today = new Date();
  let exp = new Date(today);
  exp.setDate(today.getDate() + 60);

  return jwt.sign({
    id: this._id,
    username: this.username,
    exp: parseInt(exp.getTime() / 1000),
  }, secret);
};

UserSchema.methods.toAuthJSON = function(){
    return {
        username: this.username,
        email: this.email,
        token: this.generateJWT()
  };
};


mongoose.model('User', UserSchema);

