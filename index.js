require("./utils.js");

require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
})

app.use(session({
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false,
  resave: true
}
));


app.get('/', (req, res) => {

  if (!req.session.authenticated) {
    var html = `
    <form action='/signup' method='get'>
    <button>Sign up</button>
    </form>
    <form action='/login' method='get'>
    <button>Log in</button>
    </form>
    `;
    res.send(html);
  } else {
    var username = req.session.username;

    // if (!username) {
    //   res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
    //   return;
    // }

    var html = `
      Hello, ${username}!
      <form action='/members' method='get'>
      <button>Go to Members Area</button>
      </form>
      <form action='/logout' method='get'>
      <button>Logout</button>
      </form>
      `;
    res.send(html);
  }


});

app.get('/signup', (req, res) => {
  var html = `
      create user
      <form action='/signupSubmit' method='post'>
      <input name='username' type='text' placeholder='username'> <br>
      <input name='email' type='text' placeholder='email'> <br>
      <input name='password' type='password' placeholder='password'> <br>
      <button>Submit</button>
      </form>
      `;
  res.send(html);
});

app.post('/signupSubmit', async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  if (!username) {
    var html = `
    Username is required. <br>
    <button onclick="window.location.href='/signup';">Try again.</button>
    `;
    res.send(html);
    return;
  }
  if (!email) {
    var html = `
    Email is required. <br>
    <button onclick="window.location.href='/signup';">Try again.</button>
    `;
    res.send(html);
    return;
  }
  if (!password) {
    var html = `
    Password is required. <br>
    <button onclick="window.location.href='/signup';">Try again.</button>
    `;
    res.send(html);
    return;
  }

  const schema = Joi.object(
    {
      username: Joi.string().alphanum().max(20).required(),
      email: Joi.string().max(20).required(),
      password: Joi.string().max(20).required()
    });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/createUser");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
  console.log("Inserted user");

  // var html = "successfully created user";
  // res.send(html);

  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;

  res.redirect('/members');
  return;
});

app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/');
  }
  // var cat = req.params.id;

  var username = req.session.username;
  var num = Math.floor(Math.random() * 3) + 1;
  var html = `
  <h1>Hello, ${username}!</h1>
  `;

  if (num == 1) {
    html += "<h2>Avocatdo</h2> <img src='/avocatdo.jpg' style='width:250px;'>";
  }
  else if (num == 2) {
    html += "<h2>catZoom</h2> <img src='/catZoom.jpg' style='width:250px;'>";
  }
  else if (num == 3) {
    html += "<h2>smartcat</h2> <img src='/smartcat.jpg' style='width:250px;'>";
  }
  else {
    // res.send("Invalid cat id: " + cat);
  }
  html += `
  <form action='/logout' method='get'>
  <button>Logout</button>
  </form>`

  res.send(html);
});

app.get('/login', (req, res) => {
  var html = `
      log in
      <form action='/loginSubmit' method='post'>
      <input name='email' type='text' placeholder='email'> <br>
      <input name='password' type='password' placeholder='password'> <br>
      <button>Submit</button>
      </form>
      `;
  res.send(html);
});

app.post('/loginSubmit', async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }


  const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("email not found");
    html = `
    Invalid email/password combination <br>
    <form action='/login' method='get'>
    <button>Try again</button>
    </form>`
    res.send(html);
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
    return;
  }
  else {
    console.log("incorrect password");
    html = `
    Invalid email/password combination <br>
    <form action='/login' method='get'>
    <button>Try again</button>
    </form>`
    res.send(html);
    return;
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  // var html = `
  //   You are logged out.
  //   `;
  res.redirect('/');
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
})

app.listen(port, () => {
  console.log("Node application listening on port " + port);
}); 