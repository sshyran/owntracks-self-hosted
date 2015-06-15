var config = require('../config.json');
var slack = require('slack-notify')(config.slack.webhookUrl);


module.exports = function(app) {
	app.slack = {}; 
	app.slack.sendRegisterNotification = function(user) {
		var provider = 'local'; 
		if(user.githubId)
			provider = 'github'; 
		else if(user.googleId)
			provider = 'google';	
		else if(user.twitterId)
			provider = 'twitter'; 
		else if(user.facebookId)
			provider = 'facebook'; 

		slack.send({
        		username: 'HostedBot',
        		text: "User signed up on Hosted",
        		channel: "#hosted",
        		unfurl_links: 1,
        		icon_emoji: ':bust_in_silhouette:',
        		fields: {
				'User id'   : user.id,  
        	        	'User name' : user.username,
				'Full name' : user.fullname,
        	        	'Email' : user.email,
				'Login provider' : provider 
        		}
		});
	}

}

