const passport  = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const LocalStrategy = require('passport-local');

//step2: create options for local => generate a token by correct email and password
const localOptions = {
    //by default, local strategy takes only username and password, so we define our password
    //as user email
    usernameField: 'email',
};

//step2: create local strategy
const localLogin = new LocalStrategy(localOptions, function(email, password, done){
    //verify email and password, call done with the user
    //with the correct email and password
    //otherwise call done with false
    User.findOne({email: email}, function(err, user){
        if(err){//find process has error
            return done(err);
        }

        if(!user){//didn't find a matched user
            return done(null, false);
        }
        //find the user email and
        //compare passwords
        console.log(user)
        user.comparePassword(password, function(err, isMatch){
            if(err){
                return done(err)
            }
            if(!isMatch){
                return done(null, false);
            }else{
                return done(null, user);
            }
        })
    })
});

//step1: setup options for JWT
const jwtOptions = {
    //whenever a request comes in, the passport should look at the header and find a header called 'authorization'
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret,
};

//step1: create JWT strategy => verifies user by the correct token in request header
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
    //payload => decoded jwt token {id: 'xxxxx', timestamp: 'xxxxx'}
    //done => callback function we need to call depending whether or not the authentication process is successful

    //see if the user ID in the payload is in our db, if exist, call 'done' with user object
    //otherwise call 'done' without user object

    User.findById(payload.sub, function(err, user){
        if(err){
            return done(err, false);
        }

        if(user){//find the user
            return done(null, user);
        }else{//not find the user
            return done(null, false);
        }
    })
});

//tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);