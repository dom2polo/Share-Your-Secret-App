//jshint esversion:6
require('dotenv').config(); 
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs"); 
const mongoose = require("mongoose"); 
// const encrypt = require("mongoose-encryption"); 
// const md5 = require("md5"); 
// const bcrypt = require("bcrypt"); 
// const saltRounds = 10; 
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose"); 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express(); 

app.use(express.static("public"));
app.set('view engine', 'ejs'); 
app.use(bodyParser.urlencoded({extended: true})); 

app.use(session({
    secret:  "Our little secret.",
    resave: false, 
    saveUninitialized: false
})); 

app.use(passport.initialize()); // initialize passport package 
app.use(passport.session()); // set up session 

mongoose.connect("mongodb://localhost:27017/userDB"), {useNewUrlParser: true}; 

// object created from mongoose schema 
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String, 
    secret: String
}); 

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"]}); 
userSchema.plugin(passportLocalMongoose); 
userSchema.plugin(findOrCreate); 

const User = new mongoose.model("User", userSchema); 

passport.use(User.createStrategy()); 

passport.serializeUser(function(user, done) {
    done(null, user.id); 
}); // create cookie and stuff the message 

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user) {
        done(err, user); 
    }); 
}); // allow passport to discover the message 


// configure google strategy 
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets", 
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
  }
));

// configure facebook strategy 
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


// view 
app.get("/", function(req, res) {
    res.render("home"); 
}); 


// authenticate google request 
app.get("/auth/google",
    // use passport to authenticate our user using the google strategy 
    passport.authenticate("google", { scope: ["profile"]}) 
);

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login"}), 
    function(req, res) {
        // successfully authentication, redirect home 
        res.redirect("/secrets"); 
    });  


// authenticate facebook request 
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res) {
    res.render("login"); 
}); 

app.get("/register", function(req, res) {
    res.render("register"); 
}); 

app.get("/secrets", function(req, res) {
    // we dont need to check if they're authenticated 
    User.find({"secret": {$ne: null}}, function(err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {userWithSecrets: foundUsers}); 
            }
        }
    }); // look through the secret field and pick out user where the secret field is not equal to null 
});

app.get("/submit", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");  
    } else {
        res.redirect("/login"); 
    }
}); 

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
});

app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret; 
    // find the current user and save it
    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser) {
        if (err) { 
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret; 
                foundUser.save(function() {
                    res.redirect("/secrets"); 
                });
            }
        }
    });
}); 

app.post("/register", function(req, res) {

    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log("/register"); 
        } else {
            passport.authenticate("local")(req, res, function(){ // saved cookies allow you to re-enter 
                // will expire when browsing session ends 
                res.redirect("/secrets"); 
            });
        }
    })

});

app.post("/login", function(req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function(err) {
        if (err) {
            console.log(err);
        } else {
            // successfully logged in 
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets"); 
            }); 
        }
    })

});

app.listen(3000, function() {
    console.log("Server is listening on port 3000");
}); 