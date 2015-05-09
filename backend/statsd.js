var statsd    = require('node-statsd');
var config = require('../config.json');
var StatsD = require('node-statsd');
var client = new StatsD({host: config.statsd.host, port: config.statsd.port, prefix: config.statsd.prefix, mock: !config.statsd.enabled});

module.exports = function(app) {
	app.statsd = client; 
}

