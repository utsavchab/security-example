const express = require('express')
const path = require('path')
const https = require('https')
const fs = require('fs')
const helmet = require('helmet')
const morgan = require('morgan')
const passport = require('passport')
const { Strategy } = require('passport-google-oauth20')
const cookieSession = require('cookie-session')

require('dotenv').config()
const app = express()

const GOOGLE_OAUTH_OPTIONS = {
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: '/auth/google/callback',
}

function verifyCallback(accessToken, refreshToken, profile, doneCallback) {
  console.log('Google Profile', profile.emails[0].value)
  console.log(accessToken)
  console.log(refreshToken)
  doneCallback(null, profile) // null -> No Error
}

passport.use(new Strategy(GOOGLE_OAUTH_OPTIONS, verifyCallback))
passport.serializeUser((user, done) => {
  console.log('serializing')
  done(null, user.id)
})
passport.deserializeUser((id, done) => {
  done(null, id)
})
app.use(helmet())
app.use(
  cookieSession({
    name: 'session',
    maxAge: 20 * 60 * 60 * 1000,
    keys: [process.env.COOKIE_KEY_1, process.env.COOKIE_KEY_2],
  })
)

app.use(passport.initialize())
app.use(passport.session())
app.use(morgan('dev'))

app.use(express.static('public'))

function checkIsLoggedIn(req, res, next) {
  const userAgent = req.headers['user-agent']
  console.log('useragent ', userAgent)

  console.log(req.isAuthenticated(), req.user)
  const isLoggedIn = req.isAuthenticated() && req.user //req.isAuthenticated() -> by passport
  if (!isLoggedIn) {
    res.status(404).json({
      success: false,
      message: 'You are not logged in',
    })
    return
  }
  next()
}

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['email'],
  })
) // will get here from client

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/',
    failureRedirect: '/failure',
    session: true,
  })
) // will get here from google oauth
app.get('/auth/logout', (req, res) => {
  req.logout() // by passport
  res.redirect('/')
}) // will get here if user clicks on logout
app.get('/failure', (req, res) => {
  res.send('<h1>FAILED<h1>')
})
app.get('/secret', checkIsLoggedIn, (req, res) => {
  res.send('Your Secret is 109!!')
})

app.get('/', (req, res) => {
  console.log('hello')
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

https
  .createServer(
    {
      key: fs.readFileSync('key.pem'),
      cert: fs.readFileSync('cert.pem'),
    },
    app
  )
  .listen(3000, () => console.log('Server is running'))
