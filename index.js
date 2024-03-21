const express = require('express')
const sqlite3 = require('sqlite3')
const session = require('express-session')
const { authenticator } = require('otplib')
const QRCode = require('qrcode')
const jwt = require('jsonwebtoken')
const expressJWT = require('express-jwt')
const bodyParser = require('body-parser')
const app = express()

app.set('view engine', 'ejs')

app.use(session({
  secret: 'supersecret',
}))

app.use(bodyParser.urlencoded({ extended: false }))

app.get('/', (req, res) => {
  res.render('signup.ejs')
})

app.post('/sign-up', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  const secret = authenticator.generateSecret();

  const db = new sqlite3.Database('db.sqlite');
  db.serialize(() => {
    db.run('INSERT INTO `users`(`email`, `password`, `secret`) VALUES (?, ?, ?)',
      [email, password, secret],
      (err) => {
        if (err) {
          throw err;
        }

        // Create qr
        QRCode.toDataURL(authenticator.keyuri(email, 'CBOT Test App', secret), (err, url) => {
          if (err) {
            throw err;
          }

          req.session.qr = url;
          req.session.email = email;
          req.session.password = password;
          res.redirect('/sign-up-2fa');
        });
      });
  });
});


app.get('/sign-up-2fa', (req, res) => {
  if (!req.session.qr) {
    return res.redirect('/')
  }

  return res.render('signup-2fa.ejs', { qr: req.session.qr })
})

app.post('/sign-up-2fa', (req, res) => {
  if (!req.session.email) {
    return res.redirect('/')
  }

  const email = req.session.email, password = req.session.password, code = req.body.code
  return verifyLogin(email, password, code, req, res, '/sign-up-2fa')
})

const jwtMiddleware = expressJWT({
  secret: 'supersecret',
  algorithms: ['HS256'],
  getToken: (req) => {
    return req.session.token
  }
})

app.get('/login', (req, res) => {
  return res.render('login.ejs')
})

app.post('/login', (req, res) => {
  const email = req.body.email, password = req.body.password, code = req.body.code

  return verifyLogin(email, password, code, req, res, '/login')
})

app.get('/home', jwtMiddleware, (req, res) => {
  return res.render('home.ejs', {email: req.user})
})

app.get('/logout', jwtMiddleware, (req, res) => {
  req.session.destroy()
  return res.redirect('/')
})

function verifyLogin(email, password, code, req, res, failUrl) {
  const db = new sqlite3.Database('db.sqlite');
  db.serialize(() => {
    db.get('SELECT secret, password FROM users WHERE email = ?', [email], (err, row) => {
      if (err) {
        throw err;
      }

      if (!row) {
        return res.redirect(failUrl);
      }

      if (row.password !== password) {
        return res.redirect(failUrl); 
      }

      if (!authenticator.check(code, row.secret)) {
        return res.redirect(failUrl);
      }

      req.session.qr = null;
      req.session.email = null;
      req.session.token = jwt.sign(email, 'supersecret');

      return res.redirect('/home');
    });
  });
}

//create database with tables if it doesn't exist
const db = new sqlite3.Database('db.sqlite')
db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS `users` (`user_id` INTEGER PRIMARY KEY AUTOINCREMENT, `email` VARCHAR(255) NOT NULL, `password` VARCHAR(255) NOT NULL, `secret` VARCHAR(255) NOT NULL)')
})
db.close()

app.listen(3000, () => {
  console.log(`CBOT Test APP listening at http://localhost:3000`)
})