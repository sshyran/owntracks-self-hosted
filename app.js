var config = require('./config.json');
var express = require('express');
var router = express.Router();
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var app = express();
var passport = require('passport'); 
var LocalStrategy = require('passport-local').Strategy; 
var session = require('express-session');
var RedisStore = require('connect-redis')(session);
var flash = require('connect-flash');
var Sequelize = require('sequelize');
var crypto = require('crypto');
var request = require('request-promise').defaults({ encoding: null });

var passwordOptions = {rounds: 10000, keyLength: 127, saltLength: 127}

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(require('stylus').middleware(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new RedisStore({host: "localhost", port: 6379, prefix: "traction:sess:"}),
  secret: config.SESSION_SECRET,
}));
app.use(flash());


var db = new Sequelize(config.db_name, config.db_user, config.db_password, {
    dialect: 'mariadb',
  pool: {
    max: 5,
    min: 0,
    idle: 10000
  },
});

var User = db.define('User', {
    username: Sequelize.STRING,
    salt: Sequelize.STRING,
    photo: Sequelize.TEXT,
    password:       {
        type: Sequelize.STRING,
        set:  function(v) {
          console.log(v)
            var salt = crypto.randomBytes(passwordOptions.saltLength).toString('hex');
	          var hashRaw = crypto.pbkdf2Sync(v, salt, passwordOptions.rounds, passwordOptions.keyLength)

            this.setDataValue('salt', salt);
            this.setDataValue('password', new Buffer(hashRaw, 'binary').toString('hex'));

            // Todo: recrypt all access tokens
        }
    }
  }, {
    hooks: {

    },
    classMethods: {
      findById: function(id) {
        return User.find(id);
      },
  
      findByUsername: function(username) {
        return User.find({where: {username: username}});
      }
    }, instanceMethods: {
      getDeviceTopic: function(device) {
        return "public/"+this.getUsername()+"/"+device.devicename;
      },
      getDeviceLogin: function(device) {
        return this.getUsername()+"-"+device.devicename;
      },
      getUsername: function() {
        return this.username.replace("@", "-").replace(".", "-");
      },


      authenticate: function(password, done) {
        var self = this; 
        
        var hashRaw = crypto.pbkdf2Sync(password, this.salt, passwordOptions.rounds, passwordOptions.keyLength);
        if(!hashRaw)
          return done(err);

        if (new Buffer(hashRaw, 'binary').toString('hex') === self.password) {
            return done(null, this);
        } else {
            return done(null, false, { message: 'Password is incorrect' });
        }        
      }, 
      resolveGravatar: function() {
        var queryUrl = 'http://www.gravatar.com/avatar/' +  crypto.createHash('md5').update(this.username.toLowerCase().trim()).digest('hex');
        console.log(queryUrl);

        return request({method: "GET", uri: queryUrl, resolveWithFullResponse: true}).then(function(response){
          if(response.statusCode != 200)
            return null;
          return new Buffer(response.body, 'binary').toString('base64');
        }).catch(function(error){
          console.error(error);
        })
      }

    }
  }
);

var Device = db.define('Device', {
    devicename: Sequelize.STRING,
    accessTokenHashSalt: Sequelize.STRING,
    accessTokenHash: Sequelize.STRING
}, {
  instanceMethods: {
    resetToken: function(user) {
      var token = Device.generateToken(); 
      return this.updateAttributes({accessTokenHash: token.hash, accessTokenHashSalt: token.salt}).then(function(device) {
        device.plainAccessToken = token.plain;
        return device; 
      });
    }
  },
  classMethods: {
    generateToken: function() {
      var accessToken = crypto.randomBytes(16).toString('hex');
      var accessTokenHashSalt = crypto.randomBytes(passwordOptions.saltLength).toString('hex');
      var accessTokenHashRaw = crypto.pbkdf2Sync(accessToken, accessTokenHashSalt, passwordOptions.rounds, passwordOptions.keyLength)
      var accessTokenHash = new Buffer(accessTokenHashRaw, 'binary').toString('hex')
      return {plain: accessToken, salt: accessTokenHashSalt, hash: accessTokenHash}
    },
    createForUser: function(user, devicename) {
      var token = Device.generateToken(); 
      return Device.create({devicename: devicename, UserId: user.id, accessTokenHash: token.hash, accessTokenHashSalt: token.salt}).then(function(device){
        device.plainAccessToken = token.plain; // Token is temporarily stored in the instance so it can be shown to the user once
        return device; 
      });
    }
  }
}); 

User.hasMany(Device);
Device.belongsTo(User);

sync = function() {
        return User.sync({force: false}).then(function () {
                return Device.sync({force: false});
        })
}
sync(); 
app.Device =  Device; 
app.User = User; 
app.db =  db; 



app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(
  function(username, password, done) {
    return User.findByUsername(username).then(function(user) {
      if (!user) { return done(null, false, { message: 'Unknown user ' + username }); }

      return user.authenticate(password, done);
    }).catch(function(error) {
      return done(error);
    });

  }
));


passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  return User.findById(id).then(function(user) {
    if(user)
      done(null, user);
  }).catch(function(error) {
      done(error, null);
  })
});


var syncPhoto = function(user) {
  var queryUrl = 'http://www.gravatar.com/avatar/' +  crypto.createHash('md5').update(user.username.toLowerCase().trim()).digest('hex');
  
  return request(queryUrl).then(function(body){
    console.log(body);
    return body
  }).catch(function(error){
    console.log(error);
  })

  request.get(queryUrl, function (error, response, body) {
  if (!error && response.statusCode == 200) {
          data = "data:" + response.headers["content-type"] + ";base64," + new Buffer(body).toString('base64');
          user.updateAttributes({photo: data})
  } else {
      }
  })
};



app.post('/sync', function(req,res) {
  if (!req.user) {
    return res.redirect('/login');
  }
  syncPhoto(req.user); 
   res.redirect("/")

})

// Render the registration page.
app.get('/register', function(req, res) {
  res.render('register', {title: 'Register', error: req.flash('error')[0]});
});


app.get('/devices/add', function(req, res){
  if(!req.user)
    return res.redirect("/login") 

  return res.render('devices-add', {user: req.user});

})

app.post('/devices/add', function(req, res){
  if(!req.user)
    return res.redirect("/login") 

  var name = req.body.name;
  if(!name) {
    throw new Error("devicename is required to add a new device");
  }

 return Device.createForUser(req.user, name).then(function(device){
    req.session.plainAccessToken = device.plainAccessToken; 
    device.plainAccessToken = undefined; 
    return res.redirect('/devices/'+device.id);
  }).catch(function(error){
    console.error(error);
  })
})

app.post('/devices/:id/delete', function(req, res){
  if(!req.user)
    res.redirect("/login") 

  Device.find(req.params.id).then(function(device){
    if(!device)
      res.redirect("/") 
    if(device.UserId !== req.user.id) {
      console.log("user not allowed to access device. UserId " + req.user.id + ", device.UserId " + device.UserId);
    }

    return device.destroy();
  }).then(function(){
    return res.redirect('/');
  }).catch(function(error){
    console.error(error);
    res.redirect("/")
  })
})

app.post('/devices/:id/reset', function(req, res){
  if(!req.user)
    res.redirect("/login") 

  Device.find(req.params.id).then(function(device){
    if(!device)
      res.redirect("/") 
    if(device.UserId !== req.user.id) {
      console.log("user not allowed to access device. UserId " + req.user.id + ", device.UserId " + device.UserId);
    }

    return device.resetToken();
  }).then(function(device){
    req.session.plainAccessToken = device.plainAccessToken; 
    device.plainAccessToken = undefined; 
    return res.redirect('/devices/'+device.id);
  }).catch(function(error){
    console.error(error);
    res.redirect("/")
  })
})

app.get('/devices/:id', function(req, res){
  if(!req.user)
    res.redirect("/login") 

  Device.find(req.params.id).then(function(device){
    if(!device)
      res.redirect("/") 
    if(device.UserId !== req.user.id) {
      console.log("user not allowed to access device. UserId " + req.user.id + ", device.UserId " + device.UserId);
     res.redirect("/") 
    }
    var accessToken = req.session.plainAccessToken; 
    req.session.plainAccessToken = undefined; 
    res.render('device', {device: device, user: req.user, accessToken: accessToken});
  })
})

app.post('/devices/delete', function(req, res){
  if(!req.user)
    res.redirect("/login") 
})

app.get('/start', function(req, res){
  if(!req.user)
    res.redirect("/login") 

  console.log(req.session.device);
  return res.render('start', {user: req.user, device: req.session.device});

})

app.get('/profile', function(req, res){
  if(!req.user)
    res.redirect("/login") 


  res.render('profile', {user: req.user});
})


app.post('/register', function(req, res, next) {

  var username = req.body.username;
  var password = req.body.password;
  var devicename = req.body.devicename;

  // Grab user fields.
  if (!username || !password || !devicename) {
    return res.render('register', {title: 'Register', error: 'Missing a required field required.'});
  }

  var user; 
  return User.create({username: username, password: password}).then(function(u){
    user = u; 
    return user.resolveGravatar(); 
  }).then(function(gravatar) {
     return user.updateAttributes({photo: gravatar});
  }).then(function(){
     return Device.createForUser(user, devicename)
  }).then(function(device){
      console.log("device access token: " + device.plainAccessToken);
      return; 
      return req.logIn(user, function(err) {
        if (err) { console.log(err) ; next(err)}
        req.session.device = device;  // Store device in session so first access token can be shown to user
        console.log(req.session.device);
        return res.redirect('/start');
      });

  }).catch(function(error){
    console.error(error);
  })

});


// Render the login page.
app.get('/login', function(req, res) {
  res.render('login', {title: 'Login', error: req.flash('error')[0]});
});


// Authenticate a user.
app.post('/login', passport.authenticate('local', 
  { successRedirect: '/',failureRedirect: '/login', session: true }
)); 


// Logout the user, then redirect to the home page.
app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});

app.get('/', function(req, res) {
  if(!req.user)
    return res.redirect("/login"); 

  req.app.Device.findAll({where: {UserId: req.user.id}}).then(function(devices){
    res.render('dashboard', {user: req.user, devices: devices});
  
  });
  
});



// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});


module.exports = app;
