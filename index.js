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

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

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

app.set('view engine', 'ejs');


app.get('/', (req, res) => {

  if (!req.session.authenticated) {
    res.render("index");
  } else {
    var username = req.session.username;
    res.render("verified", { username: username });
  }


});

app.get('/signup', (req, res) => {
  res.render("signup");
});

app.post('/signupSubmit', async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  if (!username) {
    res.render("signup_missing", { error: "Username" });
    return;
  }
  if (!email) {
    res.render("signup_missing", { error: "Email" });
    return;
  }
  if (!password) {
    res.render("signup_missing", { error: "Password" });
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

  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
    user_type: "user"
  });
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
  // var html = `
  // <h1>Hello, ${username}!</h1>
  // `;

  // if (num == 1) {
  //   html += "<h2>Avocatdo</h2> <img src='/avocatdo.jpg' style='width:250px;'>";
  // }
  // else if (num == 2) {
  //   html += "<h2>catZoom</h2> <img src='/catZoom.jpg' style='width:250px;'>";
  // }
  // else if (num == 3) {
  //   html += "<h2>smartcat</h2> <img src='/smartcat.jpg' style='width:250px;'>";
  // }
  // else {
  //   // res.send("Invalid cat id: " + cat);
  // }
  // html += `
  // <form action='/logout' method='get'>
  // <button>Logout</button>
  // </form>`

  res.render("members", { username: username });
});

app.get('/login', (req, res) => {
  res.render("login");
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


  const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, user_type: 1, _id: 1 }).toArray();

  console.log(result);
  if (result.length != 1) {
    res.render("login_error");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    req.session.user_type = result[0].user_type;
    res.redirect('/members');
    return;
  }
  else {
    res.render("login_error");
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

function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

app.get('/admin', async (req, res) => {
  var email = req.body.email;
  const result = await userCollection.find().project({ username: 1, user_type: 1 }).toArray();
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }
  if (isAdmin(req)) {
    res.render("admin", {
      users: result,
      username: req.session.username
    });
  } else {
    res.render("403");
  }
});

app.get("/promote/:username", async (req, res) => {
  var username = req.params.username;
  await userCollection.findOneAndUpdate(
    { username: username },
    { $set: { user_type: "admin" } }
  );
  res.redirect("/admin");

});

app.get("/demote/:username", async (req, res) => {
  var username = req.params.username;
  await userCollection.findOneAndUpdate(
    { username: username },
    { $set: { user_type: "user" } }
  );
  res.redirect("/admin");
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404.ejs");
})

app.listen(port, () => {
  console.log("Node application listening on port " + port);
}); 