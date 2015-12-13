module.exports = function (sequelize, DataTypes) {
	var app = sequelize.app; 

	var Token = sequelize.define('Token', 
		{
			id: {
				type: DataTypes.INTEGER,
				autoIncrement: true,
	      			primaryKey: true
			},
			secret: {type: DataTypes.STRING, allowNull: false},

		}, {

			instanceMethods : {

			},
			classMethods : {
				associate: function(models){
					Token.belongsTo(models.User, {foreignKey: 'userId'});
				}
			}
		}
	);
	return Token; 
}

