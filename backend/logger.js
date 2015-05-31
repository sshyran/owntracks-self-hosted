var config = require('../config.json');
var winston = require('winston');

var logger = new (winston.Logger)({ transports: [ new (winston.transports.Console)({colorize:true}) ] });

module.exports = function(app) {
	app.logger = logger; 
        app.use(require('winston-request-logger').create(logger));
}

