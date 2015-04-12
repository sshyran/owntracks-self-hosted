var express = require('express');
var router = express.Router();
var passport = require('passport');
var crypto = require('crypto');
var request = require('request').defaults({ encoding: null });


var syncPhoto = function(user) {
	var queryUrl = 'http://www.gravatar.com/avatar/' +  crypto.createHash('md5').update(user.username.toLowerCase().trim()).digest('hex');
	
	request.get(queryUrl, function (error, response, body) {
	if (!error && response.statusCode == 200) {
        	data = "data:" + response.headers["content-type"] + ";base64," + new Buffer(body).toString('base64');
        	user.updateAttributes({photo: data})
	} else {
        	console.log(error);
    	}
	})
};

router.post('/sync', function(req,res) {
  if (!req.user) {
    return res.redirect('/login');
  }
  syncPhoto(req.user); 
   res.redirect("/")

})




// Render the registration page.
router.get('/register', function(req, res) {
  res.render('register', {title: 'Register', error: req.flash('error')[0]});
});


// Register a new user to Stormpath.
router.post('/register', function(req, res) {

  var username = req.body.username;
  var password = req.body.password;

  // Grab user fields.
  if (!username || !password) {
    return res.render('register', {title: 'Register', error: 'Email and password required.'});
  }



  req.app.User.register(username, password, function(error, user) {
     if(error || !user) {
	console.log(error)
     } else {
	syncPhoto(user); 
     }
   
     res.redirect('/');
  });
});


// Render the login page.
router.get('/login', function(req, res) {
  res.render('login', {title: 'Login', error: req.flash('error')[0]});
});


// Authenticate a user.
router.post(
  '/login',   passport.authenticate('local', { successRedirect: '/',
                                   failureRedirect: '/login', session: true })
); 


// Logout the user, then redirect to the home page.
router.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});


module.exports = router;

