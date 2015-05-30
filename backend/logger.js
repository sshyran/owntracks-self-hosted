var config = require('../config.json');
var winston = require('winston');

winston.add(winston.transports.File, { filename: 'traction.log', level: 'debug' });

module.exports = function(app) {
	app.logger = winston; 
}

