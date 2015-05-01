var  jake = require("jake");

var Db = new (require('./backend/db.js'))();
var db = Db.connection;
var models = Db.models; 


task('default', [], function () {
  console.log('This is the default task.');
});

namespace('traction', function () {
	task('install', ["db:init"], function () {	  
		console.log(">> running traction:install");
	})

	task('update', ["db:update"], function () {	  
		console.log(">> running traction:update");

	})

	namespace('db', function () {
		task('update', ["migrate"], function () {	  
			console.log(">> running traction:db:update");
		})

		task('init', [], function () {	  
			console.log(">> running traction:db:init");

			return db.sync({force: true}).then(function() {
				// Create view for mosquitto auth
				return db.query("CREATE OR REPLACE VIEW Auth as select u.id, u.username, d.devicename, d.accessToken from Users as u join Devices as d where u.id = d.UserId;")
			}).catch(function(error) { 
				console.error("error: " + error); 
			});
		})

	})
})
