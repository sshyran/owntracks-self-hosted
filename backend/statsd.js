var statsd    = require('node-statsd');
var config = require('../config.json');
var StatsD = require('node-statsd');
var client = new StatsD({host: config.statsd.host, port: config.statsd.port, prefix: config.statsd.prefix, mock: !config.statsd.enabled});

var Lynx = require('lynx');
var LynxExpress = require('lynx-express');

var metrics = new Lynx(config.statsd.host, config.statsd.port, {prefix: config.statsd.prefix});
var statsdMiddleware = LynxExpress(metrics);

module.exports = function(app) {
	app.statsd = metrics; 

	app.use(statsdMiddleware({timeByUrl: true}))
}

