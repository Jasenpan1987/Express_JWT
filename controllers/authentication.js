const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user){
    //console.log(config.secret);
    const timestamp = new Date().getTime();
    return jwt.encode({sub: user.id, iat: timestamp}, config.secret)
}

exports.signup = function(req, res, next){
    var email = req.body.email;
    var password = req.body.password;
    if(!email||!password){
        return res.status(442).send({error: 'you must provide email and password'})
    }
    User.findOne({email: email}, function(err, record){
        if(err){
            return res.status(500).send({error: 'Error on creating user'});
        }

        if(record){
            return res.status(422).send({error: 'email already in use'});
        }

        const user = new User({
            email: email,
            password: password,
        });

        user.save(function(err){
            if(err){
                return res.status(500).send({error: 'Error on create user'});
            }

            return res.json({token: tokenForUser(user)});
        });
    })
};

exports.signin = function(req, res, next){
    //user has already had their email and password verified,
    //we just need to give them a token

    //when passport successfully auth a user, the user object will be accessable
    //from req.user
    var token = tokenForUser(req.user);
    res.send({token: token});
};