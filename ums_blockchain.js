/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

"use strict";
var kms = require('../utils/kms.js');
var chaincodeOps = require('../utils/chaincode_ops.js');
var user_manager = require('../utils/user_manager.js');
var sendmail = require('sendmail')();

var hfc = require('fabric-client');

// Use a tag to make logs easier to find
var TAG = "ums_blockchain.js";
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

var defaultPssword = "pass0";

var do_not_send_email = true;

var clients = {};
var channels = {};
var caClients = {};
var adminUser = null;
var appAdminUser = null;
var orgName = null;

module.exports.setup = function (pclients, pchannels, pcaClients, padminUser, pappAdminUser, porgName) {
	clients = pclients;
	channels = pchannels;
	caClients = pcaClients;
	adminUser = padminUser;
	appAdminUser = pappAdminUser;
	orgName = porgName;
	
	setupDefaultLoginUser(adminUser);
	logger.info("ums blockchain configured");
};




//============================================================
// UMS functions
//============================================================

//ready
module.exports.ready = ready;
function ready() {
	return true;
}

// set default user
module.exports.setupDefaultLoginUser = setupDefaultLoginUser;
function setupDefaultLoginUser(registrar) {
	logger.info('setupDefaultUser');
	//Do nothing
}

//update or create login user
//return error if failed, or null if succeed
module.exports.registerLoginUser = registerLoginUser;
function registerLoginUser(id, name, password, enrollId, enrollSecret, role, email, attr, cb ) {
	if (!attr) {
		attr = {};
	}
	
	if (!password || password=="") {
		//password = kms.getRandomPassword(10);
		password = defaultPssword;
		logger.debug("init password: ", password);
	}
	var userpassword = password;
	var loginUser = {
			id: id,
			name: name,
			role: role,
			enroll_id: enrollId,
			enroll_secret: enrollSecret,
			password: password,
			email: email,
			data: attr
	}
	getLoginUser(id, function(err, user) {
		if (err) {
			logger.warn("Existing user not found");
			chaincodeOps.registerLoginUser(id, loginUser, function(err, result){
				if (err != null) {
					var errmsg = "registerLoginUser error";
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));
				}
				else {
					//get token with timeoutsec 30 min
					user_manager.getLoginToken(id, userpassword, null, function(err, token) {
						if (err) {
							var errmsg = "failed to generate login token";
							logger.error(errmsg, err);
							cb && cb(new Error(errmsg));
						} else {
							logger.debug('registerUser:', result);
							//getLoginUser(id, cb);
							var link = "";
							if (hfc.getConfigSetting('enable_https')) link = "https://";
							else link ='http://';
							
							var host = hfc.getConfigSetting('host');
							var port = hfc.getConfigSetting('port');
							var mytoken = encodeURIComponent(token);
							link = link + host+":"+port+"/changePasswordLocal?token="+mytoken+"&loginID="+id;
							var alink = "<a href='"+link+"'>"+link+"</a>";
							var body = 'You are receiving this email because you '+
							'requested to reset password '+
							'or you requested to create a new account. '+
							'If you did not request either of these, '+
							'you can safely ignore this email. '+
							'To set your new password, click the provided link below to open a web page '+
							'and follow the instructions. The link is valid only for 30 minutes.<br><br>'+
							link;
							
							if (do_not_send_email) {
								logger.debug("do not sent email:");
								cb && cb(null, loginUser, body);
							}
							else {
								sendmail({
									from: 'TODO',
									to: email,
									subject: 'solution_template password change',
									html: body,
								}, function(err, reply) {
									logger.debug("sending email:");
									if (err) { 
										logger.error(err && err.stack);
										cb && cb(null, loginUser, body);
									}
									else {
										logger.debug(reply);
										cb && cb(null, loginUser, "You will receive an email confirming the registration of the user "+id+", and an instruction to set your new password"+" <br> "+alink );
									}
								});
							}
						}
					}, 30*60);
				}
			});
		} else {
			logger.warn("Existing user found");
			chaincodeOps.registerLoginUser(id, loginUser, function(err, result){
				if (err != null) {
					var errmsg = "registerLoginUser error";
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));
				}
				else {
					var errmsg = "registerLoginUser success";
					cb && cb(null, loginUser, "User updated successfully");
				}
			});
		}
	});
	

}


//return the message
module.exports.changePassword = changePassword;
function changePassword(id, password, token, cb) {
	
	user_manager.validateLoginToken(token, function(err, tokenList) {
		logger.debug("got token: ", tokenList);
		if (err) {
			logger.error("invalid token: ", err);
			cb && cb(new Error("Invalid token for the user, or token expired"));
		} else if (tokenList[1] != id) {
			cb && cb(new Error("token is not for the user"));
		} else  {
			logger.debug("token verified for "+id);
			
			getLoginUser(id, function(err, user){
				if (err) {
					logger.error("fail to get loginuser: ", err);
					cb && cb(new Error("fail to get login user"));
				} else {
					var loginUser = {
						id: user.id,
						name: user.name,
						password: password,
						enroll_id: user.enrollId,
						enroll_secret: user.enrollSecret,
						email: user.email,
						role: user.role,
						data: user.attr
					};
					chaincodeOps.registerLoginUser(id, loginUser, function(err, result){
						if (err != null) {
							var errmsg = "Error updating login user";
							logger.error(errmsg, err);
							cb && cb(new Error(errmsg));
						}
						else {
							var successmsg = "Password has been changed successfully";
							cb && cb(null, successmsg);
						}
					});
						
				}
			});

		}
	});
	
}


// return the login User object
module.exports.getLoginUser = getLoginUser;
function getLoginUser(id, cb) {
	chaincodeOps.getLoginUser(id, id, function (err, user) {
		if (err != null) {
			var errmsg = "getLoginUser error"
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));
		}
		else {
			logger.debug("loginuser found: " + id);
			var userdata = {
					id: user.id,
					name: user.name,
					password: user.password,
					email: user.email,
					role: user.role,
					enrollId: user.id,
					enrollSecret: user.enroll_secret,
					attr: user.data
			}
			cb && cb(null, userdata);
		}
	});
}

// validate userId and password
module.exports.validateLoginUser = validateLoginUser;
function validateLoginUser(id, password, data, cb) {
	chaincodeOps.getLoginUser( id, id, function (err, user) {
		if (err != null) {
			cb && cb(new Error('Failed to lookup the user. Please check the User ID and try again.'));
		}
		else {
			if (password != user.password || !user.password) {
				//password wrong
				cb & cb(new Error('User ID or Pasword does not match, or password has not been set yet'));
			}
			else {
				logger.debug("loginuser found: " + id);
				var userdata = {
						id: user.id,
						name: user.name,
						password: user.password,
						email: user.email,
						role: user.role,
						enrollId: user.id,
						enrollSecret: user.enroll_secret,
						attr: user.data
				};
				cb && cb(null, userdata);
			}
		}
	});
}

//validate user with Headers
module.exports.validateUserByHeaders = validateUserByHeaders;
function validateUserByHeaders(headers, cb) {
	try {
		var authorization = headers['authorization'];
		if (!authorization) {
			cb && cb(new Error('empty authorization'));
		}
		else {
			var b64auth = (authorization || '').split(' ')[1] || ':';
			var basicAuth = new Buffer(b64auth, 'base64').toString().split(':');
			validateLoginUser(basicAuth[0], basicAuth[1], null, function(err, user) {;
				if (err) {
					var errmsg = "error validating basic auth"; 
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));
				}
				else if (!user) {
					cb && cb(new Error('User data is empty'));
				} else {
					var timestamp = Math.floor(new Date().getTime() / 1000);
					var token = [timestamp, user.enrollId, user.enrollSecret];
					logger.debug("validating basic auth returning token:", token);
					cb && cb(null, token);
				}
			});
		}
	}
	catch (err) {
		var errmsg = "error validating basic auth";
		logger.error(errmsg, err);
		cb && cb(new Error(errmsg));
	}
}

//login user with headers
//cb not used
module.exports.loginUserByHeaders = loginUserByHeaders;
function loginUserByHeaders(req, res, next, cb) {
	next();
}

//get default password
module.exports.getDefaultPassword = getDefaultPassword;
function getDefaultPassword(cb) {
	return defaultPassword;
}

//get login url
module.exports.getLoginUrl = getLoginUrl;
function getLoginUrl(cb) {
	return "/loginLocal";
}

//get logout url
module.exports.getLogoutUrl = getLogoutUrl;
function getLogoutUrl(cb) {
	return "/logoutLocal";
}

//get changePassword url
module.exports.getChangePasswordUrl = getChangePasswordUrl;
function getChangePasswordUrl(cb) {
	return "/changePasswordLocal";
}
