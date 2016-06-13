const Authentication = require('./controllers/authentication');
const PassportService = require('./services/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', {session: false});//we don't want cookie based auth
const requireSignin = passport.authenticate('local', {session: false});

module.exports = function router(app){
    app.post('/signup', Authentication.signup);
    app.post('/signin', requireSignin, Authentication.signin);

    app.get('/resources', requireAuth, function(req, res){
        res.send({hi: 'there'})
    })
};

