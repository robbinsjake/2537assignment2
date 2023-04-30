const express = require('express');

const port = process.env.PORT || 3000;

const app = express();

app.get('/', (req,res) => {
    res.send("<h1>Hello World!</h1>");
});

app.get('/signup', (req,res) => {
    res.send("<h1>Signup Page</h1>");
});

app.get('/login', (req,res) => {
    res.send("<h1>Login Page</h1>");
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 

