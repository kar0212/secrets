require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
 
const app = express();

// console.log(process.env.API_KEY);
 
app.use(express.static("public"))
app.set('view engine','ejs')
app.use(bodyParser.urlencoded({
  extended:true
}));

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}))
 
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/userDB');

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId:String,
    secret:String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(async function (id, done) {
  let err, user;
  try {
      user = await User.findById(id).exec();
  }
  catch (e) {
      err = e;
  }
  done(err, user);
});
 

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", function(req,res){
    res.render("home")
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req,res){
    res.render("login")
})
 
app.get("/register", function(req,res){
    res.render("register")
})

app.get("/secrets",function(req,res){
  User.find({"secret":{$ne:null}})
  .then(function (foundUsers) {
    res.render("secrets",{usersWithSecrets:foundUsers});
    })
  .catch(function (err) {
    console.log(err);
    })
});

app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})

app.post("/submit", function (req, res) {
  console.log(req.user);
  User.findById(req.user)
    .then(foundUser => {
      if (foundUser) {
        foundUser.secret = req.body.secret;
        return foundUser.save();
      }
      return null;
    })
    .then(() => {
      res.redirect("/secrets");
    })
    .catch(err => {
      console.log(err);
    });
});


app.get("/logout",function(req,res){
  req.logOut(function(err){
    if(err){
      console.log(err);
    }
  });
  res.redirect("/");
})
 
app.post("/register", function(req,res){

  User.register({username:req.body.username}, req.body.password, function(err, user) {
    if (err) { 
      console.log(err);
      res.redirect("/register");
     } else {
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
      
     }
   
    });

});
 
app.post("/login", function(req,res){
  
  const user = new User({
    username:req.body.username,
    password:req.body.password
  })

  req.login(user,function(err){

    if (err) { 
      console.log(err);
      res.redirect("/login");
     } else {
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
      
     }
   
  });

})
 
app.listen(3000,function(req,res){
  console.log("Server started on port 3000.");
})
