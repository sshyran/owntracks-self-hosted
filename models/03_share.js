module.exports = function (sequelize, DataTypes) {
	var Share = 	sequelize.define('Share', 
		{
			trackedDeviceTopics: {
				type : DataTypes.STRING,
				allowNull: false
			},
		}, {
			instanceMethods : {

			},
			classMethods : {
				associate: function(){
				}
			}
		}
	);
	return Share; 
}

