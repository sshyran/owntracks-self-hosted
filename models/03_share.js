module.exports = function (sequelize, DataTypes) {
	var app = sequelize.app; 

	var Share = sequelize.define('Share', 
		{
			id: {
				type: DataTypes.INTEGER,
				autoIncrement: true,
	      primaryKey: true
			},

			trackedDeviceDevicename: {
				type : DataTypes.STRING,
				allowNull: true
			},

			accepted: {
				type: DataTypes.BOOLEAN,
				allowNull: false
			},
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
				}
			}
		}
	);
	return Share; 
}

