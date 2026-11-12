const session = require('express-session');

app.use(session({
  secret: 'keyboard cat', // @hit
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true }, // @hit
}));
