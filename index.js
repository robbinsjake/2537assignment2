require("./utils.js");
require('dotenv').config();
const express = require('express');

const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require('joi');
const MongoStore = require('connect-mongo');
const app = express();

const port = process.env.PORT || 3000;

const expireTime = 60 * 60 * 1000; // 1 hour

//Users and Passwords (in memory 'database')
var users = []; 

/*  secrets */
const node_session_secret = process.env.NODE_SESSION_SECRET;

const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
/* secrets */





var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');


app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});


app.use(session({
    secret: node_session_secret,   
    store: mongoStore, 
    saveUninitialized: false,
    resave: true

}));    

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == "admin") {
        
        return true;
    }
    

    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}


app.get('/', (req,res) => {
    if (!req.session.authenticated) {
        res.render("indexLoggedOut");        
    } else {    
        res.render("indexLoggedIn");
    }

});

app.get('/signup', (req,res) => {


    res.render("signup");

});


app.post('/signupSubmit', async (req,res) => {
    var name = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!name)  {
        res.render("invalidSignup", {error: "Name is required"});
    } else if (!email) {
        res.render("invalidSignup", {error: "Email is required"});
    } else if (!password) {
        res.render("invalidSignup", {error: "Password is required"});
    } else{
        //validate with joi

        const schema = Joi.object(
            {
                name: Joi.string().alphanum().max(20).required(),
                email: Joi.string().email().required(),
                password: Joi.string().max(20).required()
            });
    
        const validationResult = schema.validate({name, email, password});
        if (validationResult.error != null) {
           console.log(validationResult.error);
           res.redirect("/signup");
           return;
        }

    //hash password
        var hashedPassword = await bcrypt.hash(password, saltRounds);
    //save to db
        await userCollection.insertOne({name: name, email: email, password: hashedPassword, user_type: "user"});
        console.log("Inserted user");

        //redirect to members page
        req.session.authenticated = true;
        req.session.name = name;
        req.session.user_type = "user";
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    }
});


app.get('/login', (req,res) => {
    res.render("login");
});

app.post('/loginSubmit', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    if (!email) {
        res.send('Email is required <br/><br/><a href = "/login">Try again</a>');
    } else if (!password) { 
        res.send('Password is required <br/><br/><a href = "/login">Try again</a>');
    } else {  

        //validate with joi
        const schema = Joi.string().email().required();
        const validationResult = schema.validate(email);
        if (validationResult.error != null) {
                console.log(validationResult.error);
                res.redirect("/login");
                return;
        }

        //check if user exists
        const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, _id: 1, user_type:1}).toArray();

        console.log(result);

        if (result.length != 1) {
            res.render("invalidLogin");
            return;
        }
        if (await bcrypt.compare(password, result[0].password)) {
            req.session.authenticated = true;
            req.session.name = result[0].name;
            req.session.user_type = result[0].user_type;
            req.session.cookie.maxAge = expireTime;

            res.redirect('/members');

        } else {
            res.render("invalidLogin");
        }



    }
}); 

app.post('/promote', async (req,res) => {
    var email = req.body.email;
    console.log(email);
    await userCollection.updateOne({email: email}, {$set: {user_type: "admin"}});
    res.redirect('/admin');


});

app.post('/demote',  async (req,res) => {
    var email = req.body.email;
    console.log(email);
    await userCollection.updateOne({email:email}, {$set: {user_type: "user"}});
    res.redirect('/admin');

});


app.get("/admin", sessionValidation, adminAuthorization, async (req,res) => {

        var users = await userCollection.find({}).project({name: 1, user_type: 1, _id: 1, email: 1}).toArray();
        res.render("admin", {users} );
    
});



app.get("/members", sessionValidation, (req,res) => {
    res.render("members", {name: req.session.name});
});

app.use(express.static(__dirname + "/public"));

app.get("/logout", (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get("*", (req,res) => {
    res.render("status404");
});



app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 

