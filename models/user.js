const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const bcrypt = require('bcrypt-nodejs');

const userSchema = new Schema({
    email: { type:String, unique:true, lowercase:true },
    password: { type:String },
});

userSchema.pre('save', function(next){
    const user = this;
    bcrypt.genSalt(10, function(err, salt){
        if(err){
            return next(err);
        }

        bcrypt.hash(user.password, salt, null, function(err, hash){
            if(err){
                return next(err);
            }

            user.password = hash;
            next();
        })
    })
});

//add a functionality for user schema, and all the user instances will be able to call this function
userSchema.methods.comparePassword = function(candidatePassword, callback){
    const user = this;
    bcrypt.compare(candidatePassword, user.password, function(err, isMatch){
        if(err){
            return callback(err)
        }
        callback(null, isMatch);
    })
};

const ModelClass = mongoose.model('user', userSchema);

module.exports = ModelClass;