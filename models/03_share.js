module.exports = function (sequelize, DataTypes) {
	var app = sequelize.app; 

	var Share = sequelize.define('Share', 
		{
			id: {
				type: DataTypes.INTEGER,
				autoIncrement: true,
	      primaryKey: true
			},
			trackedDeviceTopic: {
				type : DataTypes.STRING,
				allowNull: false
			},
			trackedDeviceDevicename: {
				type : DataTypes.STRING,
				allowNull: false
			},

			accepted: {
				type: DataTypes.BOOLEAN,
				allowNull: false
			},
			permissions: {
				type: DataTypes.ENUM('0', '1', '2'),
				allowNull: false, 
				defaulValue: '0'
			},
			// trackedUserId: {
			// 	type: DataTypes.INTEGER, 
			// 	unique: 'Shares_trackedUserId_trackingUserId_trackedDeviceId_unique'
			// },
			// trackingUserId: {
			// 	type: DataTypes.INTEGER, 
			// 	unique: 'Shares_trackedUserId_trackingUserId_trackedDeviceId_unique'
			// },
			// trackedDeviceId: {
			// 	type: DataTypes.INTEGER, 
			// 	unique: 'Shares_trackedUserId_trackingUserId_trackedDeviceId_unique'
			// },


		}, {
		  indexes: [
		    {
		      name: 'Shares_trackedUserId_trackingUserId_trackedDeviceId_unique',
		      unique: true,
		      method: 'BTREE',
		      fields: ['trackingUserId', 'trackedUserId', 'trackedDeviceId']
		    },
		  ],

			instanceMethods : {

			},
			classMethods : {
				associate: function(models){
					Share.belongsTo(models.Device, {foreignKey: 'trackedDeviceId'});
					//Share.belongsTo(models.User, {as: "trackedUser"});
					//Share.belongsTo(models.User, {as: "trackingUser"});

				}
			}
		}
	);
	return Share; 
}

