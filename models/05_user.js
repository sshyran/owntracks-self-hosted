var crypto = require('crypto');
var config = require('../config.json')
var util = require('util')
var request = require('request-promise').defaults({
		encoding : null
});

module.exports = function (sequelize, DataTypes) {
	var app = sequelize.app; 


	var User = sequelize.define('User', 
		{
			username : {
				type : DataTypes.STRING,
				unique : true,
				allowNull : false
			},
			fullname : {
				type : DataTypes.STRING
			},
			email : {
				type : DataTypes.STRING,
				unique : true,
				allowNull : false
			},
			photo : DataTypes.TEXT,
			password : {
				type : DataTypes.STRING,
				allowNull : false,
				set : function (v) {

					var salt = crypto.randomBytes(config.passwordOptions.saltLength);
					var saltB64 = salt.toString('base64');

					var passwordHash = crypto.pbkdf2Sync(v, saltB64, config.passwordOptions.rounds, config.passwordOptions.keyLength)
						var passwordHashB64 = new Buffer(passwordHash, 'binary').toString('base64')
						var pbkdf2 = util.format("PBKDF2$%s$%d$%s$%s", config.passwordOptions.algorithm, config.passwordOptions.rounds, saltB64, passwordHashB64)

						this.setDataValue('password', pbkdf2);
				}
			},
			disabled : {
				type : DataTypes.BOOLEAN,
				defaultValue : false,
				allowNull : false
			}
		}, {
			hooks : {},
			classMethods : {
				associate: function(models){
					User.hasMany(models.Device, {foreignKey: "userId"})

					//this user is tracking bar (foo has bar as)
					//trackingUserId in Share is foo id 
					//trackedUserId in Share bar id 

					// bar is tracked by foo  (bar belongs to foo)
					//
					User.hasMany(models.User, {as: "trackedUsers", foreignKey: 'trackingUserId', otherKey: "trackedUserId", through: models.Share})
					User.belongsToMany(models.User, {as: "trackingUsers", foreignKey: 'trackedUserId', otherKey: "trackingUserId", through: models.Share})
	

					},
				findById : function (id) {
					return User.find(id);
				},

				findByUsername : function (username) {
					return User.find({
						where : {
							username : username
						}
					});
				}
			},
			instanceMethods : {

				// Resolves Gravatar and saves base64 encoded image to user instance
				updateFace : function () {
					var self = this;
					return this.resolveGravatar().then(function (image) {
						return self.updateAttributes({
							photo : image
						});
					}).then(function () {
						return self;
					});
				},

				// For subsequent device syncs. Gets new face and updates all devices
				updateFaceAndDevices : function () {
					var self = this;
					return this.updateFace().then(function () {
						return self.updateDeviceFaces();
					})
				},

				// Updates face of all devices
				updateDeviceFaces : function () {
					var self = this;

					return this.getDevices().each(function (device) {
						device.updateFace(self);
					})
				},
				clearDeviceFaces : function () {
					return this.getDevices().each(function (device) {
						device.clearDeviceFace(self);
					})
				},

				getUsername : function () {
					return this.username;
				},

				authenticate : function (password, done) {
					var pbkdf2 = this.password.split("$");

					console.log("rounds: " + parseInt(pbkdf2[2]));
					console.log("saltB64: " + pbkdf2[3]);
					console.log("hash: " + pbkdf2[4]);

					//"PBKDF2$%s$%d$%s$%s", config.passwordOptions.algorithm, config.passwordOptions.rounds, saltB64, passwordHashB64)""
					//  0                    1                          2                       3        4
					var hashRaw = crypto.pbkdf2Sync(password, pbkdf2[3], parseInt(pbkdf2[2]), config.passwordOptions.keyLength);
					if (!hashRaw)
						return done(err);

					console.log("cmp : " + new Buffer(hashRaw, 'binary').toString('base64'));

					if (new Buffer(hashRaw, 'binary').toString('base64') === pbkdf2[4]) {
						console.log("match");
						return done(null, this);
					} else {
						console.log("no match");

						return done(null, false, {
							message : 'Password is incorrect'
						});
					}
				},
				resolveGravatar : function () {
					var queryUrl = 'http://www.gravatar.com/avatar/' + crypto.createHash('md5').update(this.email.toLowerCase().trim()).digest('hex') + "?d=mm&s=40";
					console.log("Gravatar query: " + queryUrl);

					return request({
						method : "GET",
						uri : queryUrl,
						resolveWithFullResponse : true
					}).then(function (response) {
						if (response.statusCode != 200)
							return null;
						return new Buffer(response.body, 'binary').toString('base64');
					}).catch (function (error) {
						console.error(error);
					})
				},

				shareDev: function(device, toUser, rw, accepted) {
					var topic = device.getTopic(this); 
					if(this.userId == toUser.id)
						topic += "/#";

					return app.db.models.Share.create({trackingUserId: toUser.id, trackedDeviceDevicename: device.devicename, trackedDeviceTopic: topic, accepted: (accepted || false), permissions: (rw || '1'), trackedUserId: this.id, trackedDeviceId: device.id});
				},

				addDev : function (name) {
					var token = app.db.models.Device.generateToken();
					var self = this;
					var newDevice; 
					console.log(token);
					console.log(name);
					return app.db.models.Device.create({
						devicename : name,
						userId : self.id,
						accessToken : token.pbkdf2
					}).then(function (device) {
						newDevice = device; 
						newDevice.plainAccessToken = token.plain; // Token is temporarily stored in the instance so it can be shown to the user once

						return self.shareDev(newDevice, self, '2', true);
						//return app.db.models.Share.create({trackingUserId: self.id, trackedDeviceDevicename: newDevice.devicename, trackedDeviceTopic: newDevice.getTopic(self), accepted: true, permissions: '2', trackedUserId: self.id, trackedDeviceId: newDevice.id});

					}).then(function () {
						newDevice.updateFace(self);
						return newDevice;
					});
				},
			}
		}
	);
	return User;
}