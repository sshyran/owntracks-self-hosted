var mqtt    = require('mqtt');
var config = require('../config.json');
var debug = require('debug')('traction:broker');

var connectUri = 'mqtt://'+config.broker_host+":"+config.broker_port;
debug("conencting to " + connectUri);
var mqttConnection  = mqtt.connect(connectUri, {keepalive: 30, clientId: "traction", reconnectPeriod: 1000, username: config.broker_user, password: config.broker_password});

mqttConnection.on('connect', function () {
	debug("connection established");
});

mqttConnection.on('message', function (topic, message) {

});


module.exports = function() {
        this.connection = mqttConnection;
}

