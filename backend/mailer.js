var config = require('../config.json');
var nodemailer = require('nodemailer');
var ses = require('nodemailer-ses-transport');
var path = require('path');
var templatesDir = path.resolve(__dirname, '..', 'views/mailer');
var emailTemplates = require('email-templates');

var EmailAddressRequiredError = new Error('email address required');


var defaultTransport = nodemailer.createTransport(ses({
    accessKeyId: config.mailer.sesKeyId,
    secretAccessKey: config.mailer.sesKey,
    region: config.mailer.region
}));


module.exports = function(app) {	
	app.mailer = {};
	app.mailer.sendTestNotification = function(user, cb) {
		sendTemplate("test", user.email, "Test", user, cb);
	}

	app.mailer.sendRegisterNotification = function(user, cb) {
		sendTemplate("register", user.email, "Welcome to Traction", user, cb);
	}
	app.mailer.sendResetPasswort = function(user, cb) {
		sendTemplate("todo", user.email, "todo", user, cb);
	}
	app.mailer.sendPasswordChangedNotification = function(user, cb) {
		sendTemplate("todo", user.email, "todo", user, cb);
	}
	app.mailer.sendDeviceTokenResetNotification = function(userDevice, cb) {
		sendTemplate("deviceTokenReset", userDevice.user.email, "todo", userDevice, cb);
	}
	app.mailer.sendNewTrackingUserNotification = function(user, cb) {
		sendTemplate("todo", user.email, "todo", user, cb);
	}


	var sendTemplate = function (templateName, to, subject, locals, fn) {
		console.log("sending mail " +templateName + " to: " + to);
		// make sure that we have an user email
		if (!to) {
			return fn(EmailAddressRequiredError);
		}
		// make sure that we have a message
		if (!subject) {
			return fn(EmailAddressRequiredError);
		}
		console.log(templatesDir);
		emailTemplates(templatesDir, function (err, template) {
			if (err) {
				//console.log(err);
				return fn(err);
			}


			// Send a single email
			template(templateName, locals, function (err, html, text) {
				console.log("text: " + text);
								console.log("html: " + html);

				if (err) {
					//console.log(err);
					return fn(err);
				}

				var transport = defaultTransport;
				transport.sendMail({
					from: config.mailer.from,
					to: to,
					subject: subject,
					html: html
				}, function (err, responseStatus) {
					if (err) {
						app.statsd.increment("sent-mails-failed")
						return fn(err);
					}
						app.statsd.increment("sent-mails-success")
						return fn(null, responseStatus.message, html, text);
				});
			});
		});
	};
}



