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

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});


app.use(session({
    secret: node_session_secret,   
    // store: MongoStore, 
    saveUninitialized: false,
    resave: true

}));    

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
        var html = '<a href="/login"><button>LOGIN</button></a>'
        + '<br/><a href=\'/signup\'"><button>SIGNUP</button></a>';
        
    } else {    
        var html = '<a href="/members"><button>MEMBERS AREA</button></a>'
        +'</br><a href="/logout"><button>LOGOUT</button></a>';
    }
    res.send(html);
});

app.get('/signup', (req,res) => {

    var html = '<h1>Signup Page</h1>'
    + '<form method="post" action="/signupSubmit">'
    + '<input type="text" name="username" placeholder="username" >'
    + '<br/><input name="email" type="email"  placeholder="email" >'
    + '<br/><input type="password" name="password" placeholder="password" >'
    + '<br/><input type="submit" value="Signup" />'
    + '</form>';
    res.send(html);
});


app.post('/signupSubmit', async (req,res) => {
    var name = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!name)  {
        res.send('Username is required <br/><br/><a href = "/signup">Try again</a>');
    } else if (!email) {
        res.send('Email is required <br/><br/><a href = "/signup">Try again</a>');
    } else if (!password) {
        res.send('Password is required <br/><br/><a href = "/signup">Try again</a>');
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
        await userCollection.insertOne({name: name, email: email, password: hashedPassword});
        console.log("Inserted user");

        //redirect to members page
        req.session.authenticated = true;
        req.session.name = name;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    }
});


app.get('/login', (req,res) => {
    var html = '<h1>Login Page</h1>'
    + '<form method="post" action="/loginSubmit">'
    + '<input type="email" name="email" placeholder="email" />'
    + '<br/><input type="password" name="password" placeholder="password" />'
    + '<br/><input type="submit" value="Login" />'
    + '</form>';
    res.send(html);
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
        const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, _id: 1}).toArray();

        console.log(result);

        if (result.length != 1) {
            res.send('Email is incorrect <br/><br/><a href = "/login">Try again</a>');
            return;
        }
        if (await bcrypt.compare(password, result[0].password)) {
            req.session.authenticated = true;
            req.session.name = result[0].name;
            req.session.cookie.maxAge = expireTime;

            res.redirect('/members');

        } else {
            res.send('Email/password is incorrect <br/><br/><a href = "/login">Try again</a>');
        }



    }
});    



app.get("/members", (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {    
        var id = Math.floor(Math.random() * 3) + 1;
        var html = `<h1>Hello, ${req.session.name}</h1>
        <img src="/giphy${id}.gif" alt="a gif" style="width:300px"><br/>
        <a href="/logout"><button>LOGOUT</button></a>`;
        res.send(html);

    }
});
app.use(express.static(__dirname + "/public"));

app.get("/logout", (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
});



app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 

