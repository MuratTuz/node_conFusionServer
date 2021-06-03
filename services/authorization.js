var User = require('../models/user');

function unAuthenticated(res, next) {
    const err = new Error('You are not authenticated ! ');
    res.setHeader('WWW-Authenticate', 'Basic');
    err.status = 401;
    next(err);
}

exports.basicAuth = (req, res, next) => {

    const authHeader = req.headers.authorization;
    if (!authHeader) {
        unAuthenticated(res, next);
        return;
    }

    // to get ausername and password from the header 'authenticate:Basic encoded_string_for_username:password'
    const auth = new Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
    const username = auth[0];
    const password = auth[1];

    User.findOne({username: username})
    .then((user) => {
      if (user === null) {
        var err = new Error('User ' + username + ' does not exist!');
        err.status = 403;
        return next(err);
      }
      else if (user.password !== password) {
        var err = new Error('Your password is incorrect!');
        err.status = 403;
        return next(err);
      }
      else if (user.username === username && user.password === password) {
        req.session.user = 'authenticated';
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain');
        res.end('You are authenticated!')
      }
    })
    .catch((err) => next(err));

}

exports.authorization = (req, res, next) => {

    console.log(req.headers);
    if (!req.signedCookies.murat) {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            unAuthenticated(res, next);
            return;
        }

        // to get ausername and password from the header 'authenticate:Basic encoded_string_for_username:password'
        const auth = new Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
        const username = auth[0];
        const password = auth[1];

        if (username == 'admin' && password == '12345') {
            res.cookie('murat', 'admin', {
                signed: true,
                maxAge: 90000
            })
            next();
        } else {
            unAuthenticated(res, next);
        }
    } else {
        if (req.signedCookies.murat === 'admin') {
            next();
        } else {
            unAuthenticated(res, next);
        }

    }

}

exports.sessionControl = (req, res, next) => {

    console.log(req.session);
    if (!req.session.user) {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            unAuthenticated(res, next);
            return;
        }

        // to get ausername and password from the header 'authenticate:Basic encoded_string_for_username:password'
        const auth = new Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
        const username = auth[0];
        const password = auth[1];

        if (username == 'admin' && password == '12345') {
            req.session.user = 'admin';
            next(); // authorized
        } else {
            unAuthenticated(res, next);
        }
    } else {
        if (req.session.user === 'admin') {
            next();
        } else {
            unAuthenticated(res, next);
        }

    }

}

exports.sessionControlWithDb = (req, res, next) => {
    console.log(req.session);

  if(!req.session.user) {
      var err = new Error('You are not authenticated!');
      err.status = 403;
      return next(err);
  }
  else {
    if (req.session.user === 'authenticated') {
      next();
    }
    else {
      var err = new Error('You are not authenticated!');
      err.status = 403;
      return next(err);
    }
  }
}
