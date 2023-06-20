//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

// mongoose.connect("mongodb://127.0.0.1:27017/userDB");
mongoose.connect(process.env.MONGO_ATLAS_API);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    secret: String,
    googleId: String,
    facebookId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
  });
  
  passport.deserializeUser(function(obj, done) {
    done(null, obj);
  });
  

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    //callbackURL: "http://localhost:3000/auth/google/secrets",
    callbackURL: "https://secrets-vrom.onrender.com/auth/google/secrets",
    passReqToCallback: true
},
    function (request, accessToken, refreshToken, profile, done) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    // callbackURL: "http://localhost:3000/auth/facebook/secrets"
    callbackURL: "https://secrets-vrom.onrender.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
// Start Coding ///////////////////////////////////
app.get("/", (req, res)=>{
    if (req.isAuthenticated()){
        res.redirect("/secrets");
    }else{
        res.render("home");
    } 
});

app.get("/submit", (req, res)=>{
    if (req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    } 
});

app.post("/submit", (req, res)=>{
    const newSecret = req.body.secret;
    const userID = req.user._id;
    User.findById(userID)
        .exec()
        .then((foundUser) => {
            if (foundUser) {
                // Document with the given ID exists
                console.log('Document exists:', foundUser);
                foundUser.secret = newSecret;
                foundUser.save();
                res.redirect('/secrets');
            } else {
                // Document with the given ID does not exist
                console.log('Document does not exist');
                res.redirect('/secrets');
            }
        })
        .catch((err) => {
            console.log(err);
            // Handle the error
        });
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["openid"] })
);

app.get("/auth/google/secrets",
    passport.authenticate( "google", {
        successRedirect: "/secrets",
        failureRedirect: "/login"
}));

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",(req, res)=>{
    if (req.isAuthenticated()){
        res.redirect("/secrets");
    }else{
        res.render("login");
    } 
});

app.get("/register", (req, res)=>{
    if (req.isAuthenticated()){
        res.redirect("/secrets");
    }else{
        res.render("register");
    }
});

app.get("/secrets", (req, res)=>{
    if (req.isAuthenticated()){
        User.find({secret: {$ne: null}})
        .then((foundUser) => {
            res.render("secrets", {userWithSecrets: foundUser});
        })
        .catch((err) => {
            console.log(err);
            // Handle the error
        });
    }else{
        res.redirect("/login");
    }
});

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req, res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err){
        if(err){
            console.log(err);
            res.redirect("/login");
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.get('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) {
        return next(err);
      }
      res.redirect('/');
    });
  });
  
// End Coding ///////////////////////////////////
let port = process.env.Port;
if (port == null || port ==""){
    port = 3000;
}

app.listen(port, function(){
    console.log("*** App is Running on Port "+port+" ***");
});
