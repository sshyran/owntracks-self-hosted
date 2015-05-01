var Sequelize = require('sequelize');
var config = require('../config.json'); 
var lodash = require('lodash');
var debug = require('debug')('traction:db');
var fs = require('fs');
var path = require('path');

models = {};

var db = new Sequelize(config.db_name, config.db_user, config.db_password, {
	dialect: 'mariadb',
	pool: {
		max: 5,
		min: 0,
		idle: 10000
	},
	native: true, 
});

db.authenticate().then(function(err) {

}).catch(function(error){
	
	console.error("Unable to connect: " + error);
});


debug("Loading models");
fs.readdirSync(__dirname+"/../models").filter(function(file) {	
	return (file.charAt(0) != '.' &&  file.indexOf('.js') != -1) && (file.indexOf('.swp') == -1)
}).forEach(function(file){
	var model = db.import(__dirname+"/../models/"+file);	
	models[model.name] = model
})

debug("associating models");
Object.keys(models).forEach(function(modelName) {
	if ('associate' in models[modelName]) {
		console.log("Associating model: " + modelName);
		models[modelName].associate(models)
	}
})


module.exports = function() {
	this.Sequelize =  Sequelize;
	this.connection = db;
	this.models = models; 
}
