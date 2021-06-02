
function unAuthenticated(res, next) {
    const err = new Error('You are not authenticated ! ');
    res.setHeader('WWW-Authenticate', 'Basic');
    err.status = 401;
    next(err);
}

exports.authorization = (res, req, next) => {

    console.log(req.headers);

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
        next();
    } else {
        unAuthenticated(res, next);
    }
}
