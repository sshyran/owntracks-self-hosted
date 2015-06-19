var debug = require('debug')('traction:server');
var config = require('./config.json')
var http = require('http');
var express = require('express');
var router = express.Router();
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var GithubStrategy = require('passport-github2').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
var FacebookStrategy = require( 'passport-facebook' ).Strategy;

var crypto = require('crypto');
var session = require('express-session');
var RedisStore = require('connect-redis')(session);
var flash = require('connect-flash');
var mqtt = require('mqtt');
var util = require('util');
var _ =require('underscore');

var app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended : false}));
app.use(cookieParser());
app.use(require('stylus').middleware(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
		store : new RedisStore({
			host : config.redis.host,
			port : config.redis.port,
			prefix : config.redis.prefix,
		}),
		secret : config.session.secret,
		resave: true, 
		saveUninitialized: false
	}));
app.use(flash());


require('./backend/logger.js')(app);
require('./backend/db.js')(app);
require('./backend/broker.js')(app);
require('./backend/statsd.js')(app);
require('./backend/mailer.js')(app);
require('./backend/slack.js')(app);

console.log = app.logger.info; 
console.err = app.logger.error;
debug = app.logger.debug;
 
// Check supported crypto hashes
debug("Supported hashes: " + crypto.getHashes());

debug("Running pbkdf2 test vector for: sha1");
var p = "password";
var s = "salt";
var kl = 20;
var r = 1;
var h = crypto.pbkdf2Sync(p, s, r, kl);
var hf = new Buffer(h, 'binary').toString('hex');
debug("computed output : " + hf);
debug("expected output  : " + "0c60c80f961f0e71f3a9b524af6012062fe037a6");

debug("Running pbkdf2 test vector for: sha256");
var p = "password";
var s = "salt";
var kl = 32;
var r = 1;
var h = crypto.pbkdf2Sync(p, s, r, kl, "sha256");

crypto.pbkdf2(p, s, r, kl, 'sha256', function (err, key) {
	if (err)
		throw err;
	debug("checking for pbkdf2 sha256 hashes");

	debug("computed output : " + key.toString('hex'));
	debug("expected output  : " + "120fb6cffcf8b32c120fb6cffcf8b32c120fb6cffcf8b32c120fb6cffcf8b32c");
});


// Setup session and login
app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(
	function (username, password, done) {
		return app.db.models.User.findByUsername(username).then(function (user) {
			if (!user) {
				return done(username +" not found", false);
			}
			return user.authenticate(password, done);
		}).catch (function (error) {
			return done(error, false);
		});
	}
));

var profileAttributesFromGithub = function(user, profile) {
		var attributes = {}; 
		if(!user || !user.username)	
			attributes['username'] = profile.username.replace(/[^A-Za-z0-9]/gi, ''); 	
		if(!user || !user.email)	
			attributes['email'] = profile.emails[0].value;
		if(!user || !user.displayName)	
			attributes['fullname'] = profile.displayName;

		return attributes; 
}

var profileAttributesFromGoogle = function(user, profile) {
		var attributes = {}; 
		if((!user || !user.email) && profile.emails[0].value)	
			attributes['email'] = profile.emails[0].value;
		if(!user || !user.displayName)	
			attributes['fullname'] = profile.displayName;

		return attributes; 
}

var profileAttributesFromTwitter = function(user, profile) {
		var attributes = {}; 
		if(!user || !user.username)	
			attributes['username'] = profile.username.replace(/[^A-Za-z0-9]/gi, ''); 	
		if(!user || !user.displayName)	
			attributes['fullname'] = profile.displayName;

		return attributes; 
}

var profileAttributesFromFacebook = function(user, profile) {
		var attributes = {}; 
		if(!user || !user.displayName)	
			attributes['fullname'] = profile.displayName;

		return attributes; 
}


passport.use(new GithubStrategy({
    clientID: config.auth.github.clientId,
    clientSecret: config.auth.github.clientSecret,
    callbackURL: config.externalUrl+"/login/github/callback",
    passReqToCallback : true
  },
  function(req, accessToken, refreshToken, profile, done) {
		if(!req.user) { // Use is not logged in, check if we can login user
			app.logger.info("github login");
			return app.db.models.User.findOne({where: {githubId: profile.id}}).then(function(user){
				var attributes = profileAttributesFromGithub(user, profile);

				if(!user) // Create new user from Github profile
					return app.db.models.User.create(_.extend({githubId: profile.id, password: crypto.randomBytes(32).toString('hex')}, attributes));

				// Update attribute of user if needed
				return _.isEmpty(attributes) ? user : user.updateAttributes(attributes);
				
			}).then(function(user){
				return done(null, user); 
			}).catch(function(error){
				return done(error, false)
			});
		} else { // User is already logged in, link account
			app.logger.info("github link");
			return req.user.updateAttributes(_.extend({githubId: profile.id}, profileAttributesFromGithub(req.user, profile))).then(function(user){
				return done(null, user)
			}).catch(function(error){
				return done(error, false)
			});;
		}
	}
));


passport.use(new GoogleStrategy({
    clientID: config.auth.google.clientId,
    clientSecret: config.auth.google.clientSecret,
    callbackURL: config.externalUrl+"/login/google/callback",
    passReqToCallback : true
  },
	function(req, accessToken, refreshToken, profile, done) {
		console.log(profile);
		if(!req.user) { // Use is not logged in, check if we can login user
			app.logger.info("google login");
			return app.db.models.User.findOne({where: {googleId: profile.id}}).then(function(user){
				var attributes = profileAttributesFromGoogle(user, profile);

				if(!user) {// Create new user but don't save it yet
					return _.extend({temporary: true, googleId: profile.id, password: crypto.randomBytes(32).toString('hex')}, attributes);
				}

				// Update attribute of user if needed
				return _.isEmpty(attributes) ? user : user.updateAttributes(attributes);
				
			}).then(function(user){
				return done(null, user); 
			}).catch(function(error){
				return done(error, false)
			});
		} else { // User is already logged in, link account
			app.logger.info("google link")
			return req.user.updateAttributes(_.extend({googleId: profile.id}, profileAttributesFromGoogle(req.user, profile))).then(function(user){
				return done(null, user)
			}).catch(function(error){
				return done(error, false)
			});;
		}
	}
));

passport.use(new TwitterStrategy({
    consumerKey: config.auth.twitter.clientId,
    consumerSecret: config.auth.twitter.clientSecret,
    callbackURL: config.externalUrl+"/login/twitter/callback",
    passReqToCallback : true
  },
	function(req, accessToken, refreshToken, profile, done) {
		console.log(profile);
		if(!req.user) { // Use is not logged in, check if we can login user
			app.logger.info("twitter login");
			return app.db.models.User.findOne({where: {twitterId: profile.id}}).then(function(user){
				var attributes = profileAttributesFromTwitter(user, profile);

				if(!user) {// Create new user but don't save it yet
					return _.extend({temporary: true, twitterId: profile.id, password: crypto.randomBytes(32).toString('hex')}, attributes);
				}

				// Update attribute of user if needed
				return _.isEmpty(attributes) ? user : user.updateAttributes(attributes);
				
			}).then(function(user){
				return done(null, user); 
			}).catch(function(error){
				return done(error, false)
			});
		} else { // User is already logged in, link account
			app.logger.info("twitter link");
			return req.user.updateAttributes(_.extend({twitterId: profile.id}, profileAttributesFromTwitter(req.user, profile))).then(function(user){
				return done(null, user)
			}).catch(function(error){
				return done(error, false)
			});;
		}
	}
));

passport.use(new FacebookStrategy({
    clientID: config.auth.facebook.clientId,
    clientSecret: config.auth.facebook.clientSecret,
    callbackURL: config.externalUrl+"/login/facebook/callback",
    enableProof: true,
    passReqToCallback : true
  },
	function(req, accessToken, refreshToken, profile, done) {
		console.log(profile);
		if(!req.user) { // Use is not logged in, check if we can login user
			app.logger.info("facebook login");
			return app.db.models.User.findOne({where: {facebookId: profile.id}}).then(function(user){
				var attributes = profileAttributesFromFacebook(user, profile);

				if(!user) {// Create new user but don't save it yet
					console.log("building temporary facebook user");
					return _.extend({temporary: true, facebookId: profile.id, password: crypto.randomBytes(32).toString('hex')}, attributes);
				}

				// Update attribute of user if needed
				return _.isEmpty(attributes) ? user : user.updateAttributes(attributes);
				
			}).then(function(user){
				return done(null, user); 
			}).catch(function(error){
				return done(error, false)
			});
		} else { // User is already logged i)n, link account
			app.logger.info("facebook link")
			return req.user.updateAttributes(_.extend({facebookId: profile.id}, profileAttributesFromFacebook(req.user, profile))).then(function(user){
				return done(null, user)
			}).catch(function(error){
				return done(error, false)
			});;
		}
	}
));

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	return app.db.models.User.findById(id).then(function (user) {
		if (user)
			done(null, user);
	}).catch (function (error) {
		done(error, null);
	})
});




app.use(function (req, res, next) {
	// Flash messages
        res.locals.flash_success = req.flash('success');
        res.locals.flash_error = req.flash('error');

	// Token cleanup
        if(!req.session || !req.user || !req.session.deviceToken) {// no token set, no need to clear it
                return next();
        }else if(req.user.id == req.session.deviceToken.userId && (req.originalUrl === "/devices/"+req.session.deviceToken.deviceId || req.originalUrl === "/devices/"+req.session.deviceToken.deviceId+"/credentials/download" || req.originalUrl === "/devices/"+req.session.deviceToken.deviceId+"/credentials/send" )) {//token is set and target is download or send, don't clear token
                return next();
        } else { // Target is neither download nor send, clear token
                req.session.deviceToken = undefined
        }
  return next()
});


// View routes
app.post('/profile/sync', function (req, res) {
	if (!req.user) {
		return res.redirect('/login');
	}

	req.user.updateFaceAndDevices().then(function () {
		req.flash("success", "Profile synchronized.");
		res.redirect("/profile");
	})
})

app.get('/profile/link/github', passport.authorize('github', {
	scope: [ 'user:email' ], 
  successRedirect : '/profile',
	failureRedirect : '/'
	})
)
app.get('/profile/link/google', passport.authenticate('google', {
	scope: [ 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile' ],
  successRedirect : '/profile',
	failureRedirect : '/'
	})
)

app.get('/profile/link/twitter', passport.authorize('twitter', { 
  successRedirect : '/profile',
	failureRedirect : '/'
	})
)

app.get('/profile/link/facebook', passport.authorize('facebook', { 
  successRedirect : '/profile',
	failureRedirect : '/'
	})
)

app.get('/register', function (req, res) {
	res.render('register');
});

app.get('/devices/add', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

		return res.render('device-add', {
			user : req.user
		});

})




app.post('/devices/add', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	var devicename = req.body.name;
	if (!devicename) {
		req.flash("error", "A devicename is required to add a new device.");
		return res.redirect("/devices/add");
	}

	if(devicename.match(/[^A-Za-z0-9]/)) {
		req.flash("error", "The devicename may only contain alphanumeric characters");
		return res.redirect("/devices/add");
	}

	app.db.connection.transaction(function (t) {
		console.log("creating device: " + devicename);
		return req.user.addDev(devicename) 
	}).then(function (device) {
		req.session.deviceToken = device.token;
		device.token = undefined;
		req.flash("success", "Device added");
		return res.redirect('/devices/' + device.id);
	}).catch (function (error) {
		console.error(error);
		if(error.name === "SequelizeUniqueConstraintError") {
			req.flash("error", "The device already exists");
		}else {
			req.flash("error", "The device could not be created");s
		}
		return res.redirect('/devices/add');
	})
})

app.post('/devices/:id/delete', function (req, res) {
	if (!req.user)
		res.redirect("/login")

	app.db.connection.transaction(function (t) {

		return app.db.models.Device.findOne(req.params.id).then(function (device) {
			if (!device || device.userId !== req.user.id) {
				throw new Error("The object could not be found");
			}
			
			device.clearFace(req.user);
			return device.destroy();
		})
	}).then(function() {
		req.flash("success", "Device deleted.");
		return res.redirect('/');
	}).catch (function (error) {
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/")
	})
})

app.post('/devices/:id/credentials/reset', function (req, res) {
	if (!req.user)
		res.redirect("/login")

	return app.db.connection.transaction(function (t) {
		return app.db.models.Device.findOne({where: {id: req.params.id, userId: req.user.id}}).then(function (device) {
			if (!device) {
				throw new Error("The object could not be found");
			}

			return device.resetToken();
		})
	}).then(function (device) {
		req.session.deviceToken = device.token;
		device.token = undefined;
		req.flash("success", "New device credentials generated.");

		return res.redirect('/devices/' + device.id);
	}).catch (function (error) {
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/")
	})
})

app.get('/devices/:id', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	return app.db.connection.transaction(function (t) {
		return app.db.models.Device.findOne({where: {id: req.params.id, userId: req.user.id}})
	}).then(function (device) {
		if (!device) {
			throw new Error("The object could not be found");
		}

		var deviceToken; 
		if(req.session.deviceToken && req.session.deviceToken.deviceId == device.id && req.session.deviceToken.userId == req.user.id)
			deviceToken = req.session.deviceToken;
		var firstStart = req.session.firstStart;
		// Clean up session
		req.session.firstStart = undefined
		
		res.render('device', {
			device : device,
			user : req.user,
			deviceToken : deviceToken,
			firstStart : firstStart != undefined
		});
	}).catch (function (error) {
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/")
	});
	
})

app.get('/devices/:id/credentials/download', function (req, res) {
	if(!req.user)
		return res.redirect("/login");

	var deviceToken;
        if(req.session.deviceToken && req.session.deviceToken.deviceId == req.params.id && req.session.deviceToken.userId == req.user.id)
        	deviceToken = req.session.deviceToken
	else {
		req.flash("error", "Please generate new creadentials for this device to download them");
                return res.redirect("/devices/"+req.params.id)
	}
  
        return app.db.models.Device.findOne({where: {id: req.params.id, userId: req.user.id}}).then(function (device) {
	        if (!device) {
       	         throw new Error("The object could not be found");
               }
       
		res.setHeader('Content-disposition', 'attachment; filename=' + req.user.username+"-"+device.devicename+".otrc");
		res.setHeader('Content-type', 'application/json');
		res.charset = 'UTF-8';
		res.send(device.getOtrcPayload(req.user, deviceToken));
	}).catch (function (error) {
                req.flash("error", error.toString().replace("Error: ", ""));
                return res.redirect("/")
        });
});

app.post('/devices/:id/credentials/send', function (req, res) {
      if(!req.user)
          return res.redirect("/login");

        var deviceToken;
        if(req.session.deviceToken && req.session.deviceToken.deviceId == req.params.id && req.session.deviceToken.userId == req.user.id)
                deviceToken = req.session.deviceToken
        else {
                req.flash("error", "Please generate new creadentials for this device to download them");
                return res.redirect("/devices/"+req.params.id)
        }

        return app.db.models.Device.findOne({where: {id: req.params.id, userId: req.user.id}}).then(function (device) {
                if (!device) {
                 throw new Error("The object could not be found");
               }
		
		app.mailer.sendDeviceToken({user: req.user, device: device, payload: device.getOtrcPayload(req.user, deviceToken)}, function(error, code){
			if(!error)
		        	req.flash("success", "A mail containing the device credentials has been sent to you");
                	else
				req.flash("error", "An error occured while sending a mail, please try again later"); 	
			return res.redirect("/devices/"+req.params.id)
		})
        }).catch (function (error) {
                req.flash("error", error.toString().replace("Error: ", ""));
                return res.redirect("/")
        });

});



app.get('/trackers/add', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	return app.db.connection.transaction(function (t) {
		return req.user.getDevices();
	}).then(function (devices) {
		if (devices.length == 0) {
			throw new Error("Please add a device first");
		}

		return res.render('tracker-add', {
			user : req.user,
			devices: devices
		});

	}).catch (function (error) {
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/")
	})
})


app.post('/tracking/:id/accept', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	if(!req.params.id)
		return res.redirect("/")


	var trackedUser; 
	var share; 
	
	return app.db.connection.transaction(function (t) {
		return app.db.models.Share.findOne({where: {id: req.params.id, trackingUserId: req.user.id}}).then(function(s){
			share = s; 

			if (!share) {
				throw new Error("The object could not be found");
			}

			return share.updateAttributes({accepted: true});
		})
	}).then(function(){
		req.flash("success", "Tracking accepted");
		return res.redirect("/tracking/"+share.id);
	}).catch(function(error){
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/");
	});
})

app.post('/tracking/:id/delete', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	if(!req.params.id)
		return res.redirect("/")


	var trackedUser; 
	var share; 
	
	return app.db.connection.transaction(function (t) {

		return app.db.models.Share.find(req.params.id).then(function(s){
			share = s; 

			if (!share || share.trackingUserId !== req.user.id) {
				throw new Error("The object could not be found");
			}

			return share.destroy();
		})
	}).then(function(){
		req.flash("success", "Tracking removed");
		return res.redirect("/");
	}).catch(function(error){
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/");
	});
})


app.get('/tracking/:id', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	var share; 
	
	return app.db.connection.transaction(function (t) {

		return app.db.models.Share.findOne({where: {id: req.params.id, trackingUserId: req.user.id}}).then(function(s){
			share = s; 
			
			if (!share) {
				throw new Error("The object could not be found");
			}

			return app.db.models.User.find(share.trackedUserId);
		})
	}).then(function(trackedUser){

			return res.render('tracking', {
				user : req.user, 
				trackedUser: trackedUser,
				share: share
			});

		}).catch(function(error){
			req.flash("error", error.toString().replace("Error: ", ""));
			return res.redirect("/");
		});


})

app.get('/trackers/:id', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	var share; 
	
	return app.db.connection.transaction(function (t) {
		return app.db.models.Share.findOne({where: {id: req.params.id, trackedUserId: req.user.id}}).then(function(s){
			share = s; 
			if (!share ) {
				throw new Error("The object could not be found");
			}
				
			return app.db.models.User.find(share.trackingUserId);
		})
	}).then(function(trackingUser){
		return res.render('tracker', {
			user : req.user, 
			trackingUser: trackingUser,
			share: share
		});

	}).catch(function(error){
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/");
	});

})

app.post('/tracker/:id/delete', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	if(!req.params.id)
		return res.redirect("/")


	var trackedUser; 
	var share; 
	
	return app.db.connection.transaction(function (t) {

		return app.db.models.Share.find({where: {id: req.params.id, trackedUserId: req.user.id}}).then(function(s){
			share = s; 

			if (!share) {
				throw new Error("The object could not be found");
			}

			return share.destroy();
		});
		
	}).then(function(){
		req.flash("success", "Tracker removed");
		return res.redirect("/");
	}).catch(function(error){
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/");
	});
})


app.post('/trackers/add', function (req, res) {
	if (!req.user)
		return res.redirect("/login")

	var username = req.body.username;
	var deviceId = req.body.deviceId;

	console.log("deviceId: " +deviceId)
	if (!username) {
		req.flash("error", "A username is required to add a tracker");
		return res.redirect("/devices/"+req.params.id+"/trackers/add");
	}

	if(!deviceId) {
		req.flash("error", "A device is required to add a tracker");
		return res.redirect("/trackers/add");
	}

	if(username == req.user.username) {
                req.flash("error", "You cannot add yourself as a tracker");
		return res.redirect("/trackers/add");
	}

	var device; 
	var targetUser; 


	return app.db.connection.transaction(function (t) {

		return app.db.models.Device.findOne({where: {id: deviceId, userId: req.user.id}}).then(function (d) {
			device = d;

			if (!device) {
				throw new Error("The object could not be found");
			}


			return app.db.models.User.findOne({where: {username: username}});

		}).then(function(t){
			targetUser = t;

			if(!targetUser) {
				throw new Error("The specified user does not exist");
			}

			return app.db.models.Share.find({where: {trackedUserId: req.user.id, trackingUserId: targetUser.id, trackedDeviceId: device.id}})
		}).then(function(share){
			if(share) {
				throw new Error("This device is already tracked by " + targetUser.username);
			}

			return req.user.shareDev(device, targetUser);
		})
	}).then(function(){
		req.flash("success", "The user has been invited to track your device");
		return res.redirect("/");
	}).catch(function(error){
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/trackers/add");

	})
})

app.get('/profile', function (req, res) {
	if (!req.user)
		res.redirect("/login")

		res.render('profile', {
			user : req.user
		});
})

app.get('/profile/edit', function (req, res) {
	if (!req.user)
		res.redirect("/login")

		res.render('profile-edit', {
			user : req.user
		});
})
app.get('/profile/recover', function (req, res) {
	// Not for logged in users
	if (req.user)
		res.redirect("/")

	res.render('profile-recover', {
	});
})

app.post('/profile/recover', function (req, res) {
	// Not for logged in users
	if (req.user)
		res.redirect("/")

	var email = req.body.email;
	if(!email) {
		req.flash('error', "An email address is required.");
		res.redirect('/');
	}

	return app.db.connection.transaction(function (t) {

		return app.db.models.User.findOne({where: {email: email}}).then(function (user){
			if(!user) {
				throw new Error("We send you a recovery link"); // Don't give away that the user was not found
			}

			var tokenRaw = crypto.randomBytes(20);
			var token = tokenRaw.toString('hex');

			var expires = new Date();
			expires.setTime(expires.getTime()+3600000);

			return user.updateAttributes({passwordResetToken: token, passwordResetTokenExpires: expires});

		})
	}).then(function(user) {
		app.mailer.sendPasswordResetLink(user);
		req.flash('success', "We send you a recovery link");
		res.redirect('/profile/recover');
	}).catch(function(error) {
		console.error(error);
		req.flash("success", error.toString().replace("Error: ", "")); // Don't give away errors here
		res.redirect('/profile/recover');
	})
})

app.get('/profile/reset/:token', function (req, res) {
	// Not for logged in users
	if (req.user)
		res.redirect("/")

	if(!req.params.token) {
		req.flash("error", "No reset token was provided");
		return res.redirect("/profile/recover");
	}

	return app.db.connection.transaction(function (t) {
		return app.db.models.User.findOne({where: {passwordResetToken: req.params.token, passwordResetTokenExpires: {gt: new Date()}}}).then(function(user) {
			if(!user) {
				throw new Error("Password reset token is invalid or has expired");
			}

			return res.render('profile-reset', {
				user: user,
				token: req.params.token
			});
		})
	}).catch(function(error) {
		console.error(error);
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/profile/recover");
	})
});

app.post('/profile/reset/:token', function (req, res) {
	// Not for logged in users
	if (req.user)
		res.redirect("/")

	var password = req.body.newPassword; 
	var passwordRepeat = req.body.newPasswordRepeat; 

	if(!req.params.token) {
		req.flash("error", "No reset token was provided");
		return res.redirect("/profile/recover");
	}

	if(!password || !passwordRepeat) {
		req.flash("error", "A password is requried");
		return res.redirect("/profile/reset/"+req.params.token);
	}

	if(password !== passwordRepeat) {
		req.flash("error", "Passwords do not match");
		return res.redirect("/profile/reset/"+req.params.token);
	}

	return app.db.connection.transaction(function (t) {
		return app.db.models.User.findOne({where: {passwordResetToken: req.params.token, passwordResetTokenExpires: {gt: Date.now()}}}).then(function(user) {
			if(!user) {
				throw new Error("Password reset token is invalid or has expired");
			}

			return user.updateAttributes({password: password, passwordResetToken: null, passwordResetTokenExpires: null});

		})
	}).then(function(user){
		return req.logIn(user, function(err) {
			req.flash("success", "Password updated");
			app.mailer.sendPasswordChangedNotification(user);
			return res.redirect("/");
		});

	}).catch(function(error) {
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/profile/recover");
	})
});



app.post('/profile/delete', function (req, res, next) {
	if (!req.user)
		res.redirect("/login")


	return req.user.destroy().then(function(user) {
		req.flash('success', "Your profile was deleted");
		req.logout();
		return res.redirect('/');
	}).catch(function(error) {
		req.flash("error", error.toString().replace("Error: ", ""));
		return res.redirect("/profile");
	})
})

app.post('/profile/edit', function (req, res, next) {
	if (!req.user)
		res.redirect("/login")

		var currentPassword = req.body.currentPassword;

	var email = req.body.email;
	var newPassword = req.body.newPassword;
	var newPasswordRepeat = req.body.newPasswordRepeat;
	var fullname = req.body.fullname;

	if (email != req.user.email && !newPassword && !fullname) {
		req.flash('error', "There was nothing to update");
		return res.redirect('/profile/edit');
	}

	return req.user.authenticate(currentPassword, function (error, user, message) {
		if (error || !user) {
			req.flash('error', "Incorrect current password");
			return res.redirect('/profile/edit');
		}

		if (newPassword != newPasswordRepeat) {
			req.flash("error", "New passwords do not match");
			return res.redirect('/profile/edit');
		}

		var update = {};
		if (email)
			update['email'] = email;

		if (fullname)
			update['fullname'] = fullname;

		if (newPassword)
			update['password'] = newPassword

			
		return app.db.connection.transaction(function (t) {	
			return user.updateAttributes(update)
		}).then(function(user){
			return user.updateDeviceFaces();
		}).then(function () {
			req.flash("success", "Profile updated.");
			return res.redirect('/profile');
		}).catch (function (error) {
			req.flash("error", error.toString().replace("Error: ", ""));
			return res.redirect('/profile/edit');
		})
	})
})

app.post('/register', function (req, res, next) {

	var username = req.body.username;
	var email = req.body.email;
	var password = req.body.password;
	var devicename = req.body.devicename;
	var fullname = req.body.fullname;

	if (!username || !password || !devicename || !email | !fullname) {
		req.flash("error", "Missing a required field");
		return res.render('register');
	}


	if(username.match(/[^A-Za-z0-9]/)) {
		req.flash("error", "The username may only contain alphanumeric characters");
		return res.redirect('/register');
	}


	if(devicename.match(/[^A-Za-z0-9]/)) {
		req.flash("error", "The devicename may only contain alphanumeric characters");
			return res.redirect('/register');
	}


	var user;
	var device; 

	return app.db.connection.transaction(function (t) {
		return app.db.models.User.create({
			username : username,
			email : email,
			password : password,
			fullname: fullname
		}).then(function (u) {
			user = u; 
			return user.addDev(devicename)
		})
	}).then(function(d){
		device = d; 

		return req.logIn(user, function (err) {
			if (err) {
				console.log(err);
				next(err)
			}

			req.session.deviceToken = device.token;
			device.token = undefined;
			req.session.firstStart = true;

			return res.redirect('/devices/' + device.id);
		});
	}).catch (function (error) {
			if(error.name === "SequelizeUniqueConstraintError") {
				req.flash("error", "A user with the specified details already exist");
			}else {
				req.flash("error", error.toString().replace("Error: ", ""));
			}

			return res.redirect("/register");
	});
});


var authCallback = function(req, res, next, err, user) {	
	if(!user || err) {
		//console.log("authCallback primary error: ");
		app.logger.warn("primary auth failure for user: " + err);
		//app.logger.warn(err);

		req.flash("error", "Login failed");
		return res.redirect("/login");
	}
	return req.logIn(user, function(error) {
		if(error) {
			app.logger.error("secondary auth failure for user");
			app.logger.error(error);

			req.flash("error", "Login failed");
			return res.redirect("/login");
		}
		return res.redirect("/");
	});
}

// Local login
app.get('/login', function (req, res) {res.render('login');});
app.post('/login', function(req, res, next) {
	return passport.authenticate('local', function(err, user) {return authCallback(req, res, next, err, user)})(req, res, next); 
});

// Github login
app.get('/login/github', passport.authenticate('github', {scope: [ 'user:email' ]}));
app.get('/login/github/callback', function(req, res, next) {
	return passport.authenticate('github', function(err, user) {return authCallback(req, res, next, err, user)})(req, res, next); 
});

// Google login
app.get('/login/google', passport.authenticate('google', {scope: [ 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile' ]}));
app.get('/login/google/callback', function(req, res, next) {
		return passport.authenticate('google', function(err, user) {

			if(err || !user || !user.temporary){  
				return authCallback(req, res, next, err, user)
			}else { 
				req.session.temporaryUserGoogle = user; 
				return res.redirect("/login/google/finish");
			}

		})(req, res, next); 
});
app.get('/login/google/finish', function(req, res, next) {
		return res.render('profile-finish-google');
});
app.post('/login/google/finish', function(req, res, next) {
	var user = req.session.temporaryUserGoogle;

	if(!user || !req.body.username || req.body.username == "") {
		return authCallback(req, res, next, new Error("no user or username"), null)
	}

        if(req.body.username.match(/[^A-Za-z0-9]/)) {
		return authCallback(req, res, next, new Error("The username may only contain alphanumeric characters"), null)
        }
	
	user.username = req.body.username; 

	app.db.models.User.create(user).then(function(u) {
		console.log("user saved");
		return authCallback(req, res, next, null, u)		
	}).catch(function(err) {
		console.log(err);
		return authCallback(req, res, next, err, null)
	}); 

});


// Twitter login
app.get('/login/twitter', passport.authenticate('twitter'));
app.get('/login/twitter/callback', function(req, res, next) {
		return passport.authenticate('twitter', function(err, user) {

			if(err || !user || !user.temporary){  
				return authCallback(req, res, next, err, user)
			}else { 
				req.session.temporaryUserTwitter = user; 
				return res.redirect("/login/twitter/finish");
			}

		})(req, res, next); 
});
app.get('/login/twitter/finish', function(req, res, next) {
		return res.render('profile-finish-twitter');
});
app.post('/login/twitter/finish', function(req, res, next) {
	var user = req.session.temporaryUserTwitter;

	if(!user || _.isEmpty(req.body.email)) {
		return authCallback(req, res, next, new Error("no user or email"), null)
	}
	
	user.email = req.body.email; 

	app.db.models.User.create(user).then(function(u) {
		console.log("user saved");
		return authCallback(req, res, next, null, u)		
	}).catch(function(err) {
		console.log(err);
		return authCallback(req, res, next, err, null)
	}); 

});

// Twitter login
app.get('/login/facebook', passport.authenticate('facebook'));
app.get('/login/facebook/callback', function(req, res, next) {
		return passport.authenticate('facebook', function(err, user) {

			if(err || !user || !user.temporary){  
				return authCallback(req, res, next, err, user)
			}else { 
				req.session.temporaryUserFacebook = user; 
				return res.redirect("/login/facebook/finish");
			}

		})(req, res, next); 
});
app.get('/login/facebook/finish', function(req, res, next) {
		return res.render('profile-finish-facebook');
});
app.post('/login/facebook/finish', function(req, res, next) {
	var user = req.session.temporaryUserFacebook;

	if(!user || _.isEmpty(req.body.username) || _.isEmpty(req.body.email)) {
		return authCallback(req, res, next, new Error("no user or username or email"), null)
	}

        if(req.body.username.match(/[^A-Za-z0-9]/)) {
                return authCallback(req, res, next, new Error("The username may only contain alphanumeric characters"), null)
        }
	
	user.username = req.body.username; 
	user.email = req.body.email; 

	app.db.models.User.create(user).then(function(u) {
		console.log("user saved");
		return authCallback(req, res, next, null, u)		
	}).catch(function(err) {
		console.log(err);
		return authCallback(req, res, next, err, null)
	}); 

});




app.get('/logout', function (req, res) {
	req.logout();
	res.redirect('/');
});

app.get('/', function (req, res) {
	if (!req.user)
		return res.redirect("/login");

	var trackedUsers;
	var trackingUsers;

	return app.db.connection.transaction(function (t) {

		return req.user.getTrackedUsers().then(function(t){
			trackedUsers = t; 
			return req.user.getTrackingUsers();
		}).then(function(t){
			trackingUsers = t; 
			return req.user.getDevices();
		})
	}).then(function (devices) {
		res.render('dashboard', {
			user : req.user,
			devices : devices,
			trackingUsers: trackingUsers,
			trackedUsers: trackedUsers			
		});
	});
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {


	res.status(404)

	res.render('404', {
		user : req.user,
	});		
});




// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
		app.use(function (err, req, res, next) {
		res.status(err.status || 500);
		res.render('error', {
			message : err.message,
			error : err
		});
	});
}

// production error handler
// no stacktraces leaked to user
app.use(function (err, req, res, next) {
	res.status(err.status || 500);
	res.render('error', {
		message : err.message,
		error : {}
	});
});



// Setup and run server
var port = normalizePort(config.port || '3000');
app.set('port', port);
var server = http.createServer(app);

server.listen(port);
server.on('error', onError);
server.on('listening', onListening);

function normalizePort(val) {
	var port = parseInt(val, 10);

	if (isNaN(port)) {
		// named pipe
		return val;
	}

	if (port >= 0) {
		// port number
		return port;
	}

	return false;
}

function onError(error) {
	if (error.syscall !== 'listen') {
		throw error;
	}

	var bind = typeof port === 'string'
		 ? 'Pipe ' + port
		 : 'Port ' + port;

	// handle specific listen errors with friendly messages
	switch (error.code) {
	case 'EACCES':
		console.error(bind + ' requires elevated privileges');
		process.exit(1);
		break;
	case 'EADDRINUSE':
		console.error(bind + ' is already in use');
		process.exit(1);
		break;
	default:
		throw error;
	}
}

function onListening() {
	var addr = server.address();
	var bind = typeof addr === 'string'
		 ? 'pipe ' + addr
		 : 'port ' + addr.port;
	debug('Listening on ' + bind);
}
