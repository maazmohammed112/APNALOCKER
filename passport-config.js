const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/User');

function initialize(passport) {
    passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
        const user = await User.findOne({ email });
        if (!user) {
            return done(null, false, { message: 'No user with that email' });
        }
        // Add password verification here
        return done(null, user);
    }));

    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id); // Use await to handle the promise
            done(null, user);
        } catch (error) {
            done(error);
        }
    });
}

module.exports = initialize;
