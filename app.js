//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const saltRounds = 10;
// const md5 = require("md5");
// const encrypt = require('mongoose-encryption');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://127.0.0.1:27017/userDB");
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

const User = new mongoose.model("User", userSchema);
// Start Coding ///////////////////////////////////
app.get("/", (req, res)=>{
    res.render("home");
});

app.get("/login",(req, res)=>{
    res.render("login");
});

app.get("/register", (req, res)=>{
    res.render("register");
});

app.post("/register", (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email: req.body.username,
            password: hash
        })
        newUser.save()
            .then(()=>{
                res.render('secrets');
            })
            .catch((err) => {
                    console.log(err);
            })
    }); 
});

app.post("/login", (req, res)=>{
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({
        email: username
    })
    .then((foundUser)=>{
        if (foundUser){
            bcrypt.compare(password, foundUser.password, function(err, result) {
                if (result === true){
                    res.render("secrets");
                }else{
                    res.send("Incorrect Password");
                }
            });
        }else{
            res.send("Email Doesn't Exist");
        }
    })
    .catch((err)=>{
        console.log(err);
    })
})
// End Coding ///////////////////////////////////
app.listen(3000,()=>{
    console.log("** App Started on Port 3000");
});
