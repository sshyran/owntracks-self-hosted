module.exports = function (sequelize, DataTypes) {
	var Device = sequelize.define('Device', 
		{
			devicename : {
				type : DataTypes.STRING,
				allowNull : false
			},
			accessToken : DataTypes.STRING,
		}, {
			instanceMethods : {
				resetToken : function (user) {
					var token = Device.generateToken();

					return this.updateAttributes({
						accessToken : token.pbkdf2
					}).then(function (device) {
						device.plainAccessToken = token.plain;
						return device;
					});
				},

				updateFace : function (user) {
					console.log("updating device face of device: " + this.id);
					var face = {
						"_type" : "card",
						"name" : user.username,
						"face" : user.photo
					};
					return mqttConnection.publish(this.getFaceTopic(user), JSON.stringify(face), {
						qos : 0,
						retain : true
					});
				},

				clearFace : function (user) {
					return mqttConnection.publish(this.getFaceTopic(user), "", {
						qos : 0,
						retain : true
					});
				},
				getTopic : function (user) {
					return config.topic_prefix + "/" + user.getUsername() + "/" + this.devicename;
				},
				getFaceTopic : function (user) {
					return this.getTopic(user) + "/info";
				},
				getLogin : function (user) {
					return user.getUsername() + "|" + this.devicename;
				},

			},
			classMethods : {
				associate: function(){
					Device.belongsTo(models.User);
					Device.belongsToMany(models.Share);
				},
				generateToken : function () {
					var accessToken = crypto.randomBytes(16).toString('base64');
					var accessTokenHashSalt = crypto.randomBytes(config.passwordOptions.saltLength);
					var accessTokenHashSaltB64 = accessTokenHashSalt.toString('base64');

					var accessTokenHash = crypto.pbkdf2Sync(accessToken, accessTokenHashSaltB64, config.passwordOptions.rounds, config.passwordOptions.keyLength, config.passwordOptions.algorithm)
						var accessTokenHashB64 = new Buffer(accessTokenHash, 'binary').toString('base64')
						var pbkdf2 = util.format("PBKDF2$%s$%d$%s$%s", config.passwordOptions.algorithm, config.passwordOptions.rounds, accessTokenHashSaltB64, accessTokenHashB64)

						return {
						plain : accessToken,
						pbkdf2 : pbkdf2
					}
				}
			}
		}
	);
	return Device; 
}

