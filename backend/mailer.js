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

	app.mailer.sendRegisterNotification = function(user, cb) {
		sendTemplate("register", user.email, "Welcome", user, cb);
	}
	app.mailer.sendPasswordResetLink = function(user, cb) {
		sendTemplate("passwordReset", user.email, "Password reset", user, cb);
	}
	app.mailer.sendPasswordChangedNotification = function(user, cb) {
		sendTemplate("passwordChanged", user.email, "Password changed", user, cb);
	}
	app.mailer.sendDeviceToken = function(userDevice, cb) {
		sendTemplate("deviceToken", userDevice.user.email, "Device credentials", userDevice, cb, {
			filename: userDevice.user.username+"-"+userDevice.device.devicename+".otrc", 
			content: JSON.stringify(userDevice.payload), 
			contentType: "application/json", 
			encoding: "utf8",
			contentDisposition: "attachment; filename=" + userDevice.user.username+"-"+userDevice.device.devicename+".otrc"
		});
	}
	app.mailer.sendNewTrackingUserNotification = function(user, cb) {
		sendTemplate("newTracker", user.email, "New tracker", user, cb);
	}


	var sendTemplate = function (templateName, to, subject, locals, fn, attachment) {
		console.log("sending mail " +templateName + " to: " + to);
		// make sure that we have an user email
		if (!to) {
			return fn(EmailAddressRequiredError);
		}
		// make sure that we have a message
		if (!subject) {
			return fn(EmailAddressRequiredError);
		}
		emailTemplates(templatesDir, function (err, template) {
			if (err) {
				//console.log(err);
				return fn(err);
			}


			// Send a single email
			template(templateName, {config: config, data: locals}, function (err, html, text) {
				if (err) {
					//console.log(err);
					return fn(err);
				}

				var transport = defaultTransport;
				transport.sendMail({
					from: config.mailer.from,
					to: to,
					subject: "[OwnTracks Hosted] " + subject,
					html: html,
					attachments: attachment ? [attachment] : undefined
				}, function (err, responseStatus) {
					if (err) {
						app.statsd.increment("sent-mails-failed")
						return fn(err);
					}
						app.statsd.increment("sent-mails-success")
					if(fn)
						return fn(null, responseStatus.message, html, text);
				});
			});
		});
	};
}



