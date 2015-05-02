var  jake = require("jake");
var app = {};
var db = require('./backend/db.js')(app);

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

			return app.db.connection.sync({force: true}).then(function() {
				// Create view for mosquitto auth
				return app.db.connection.query("CREATE OR REPLACE VIEW Auth as select u.id, u.username, d.devicename, d.accessToken from Users as u join Devices as d where u.id = d.UserId;")
			}).then(function() {
				// Sequelize creates a unique index for trackedUserId and trackingUserId
				// There might however be entries with duplicate trackedUserId and trackingUserId if a user has more than one device 
				// The Share model defines a new index that also includes the trackedDeviceId in an unique index so the Shares_trackedUserId_trackingUserId_unique one is redundant and wrong
				// It can safely be dropped as the new index includes all components in the same order to maintain foreign key integrity
				console.log("Fixing indices of Shares table");
				return app.db.connection.query("DROP INDEX `Shares_trackedUserId_trackingUserId_unique` on `Shares`");
			}).catch(function(error) { 
				console.error("error: " + error); 
			});
		})

	})
})
