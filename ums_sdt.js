/*******************************************************************************
 * 
 * 
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 * 
 *******************************************************************************/

"use strict";
var request = require('request');

// This connector let's us register users against a CA

var request_handler = require('../utils/request_handler.js');

var dummyPW = "dummy";
var baseUrl = "https://10.155.180.10:9811/ums/UserMgmtService/";
var applicationID = "blckchn";
var tenantID = "hyperledger";
var instanceID = "inst1";
var junctionID = "/bcn";
var userID = "blckchn_ADMIN";
var userPW = "ums4bchain";
var serverHost = "10.155.176.12"; 
var serverPort = 3000;
var umsReady = false;

var defaultEmail = "TODO";

// Use a tag to make logs easier to find
var TAG = "ums_sdt.js";
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var hfc = require('fabric-client');
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

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
	
	logger.debug("userID=", userID);
	logger.debug("userPW=", userPW);
	logger.debug("baseUrl=", baseUrl);
	logger.debug("applicationID=", applicationID);
	logger.debug("tenantID=", tenantID);
	logger.debug("instanceID=", instanceID);
	logger.debug("junctionID=", junctionID);	
	
	//setup ums blockchain
	//ums_blockchain.setup(clients, channels, caClients, adminUser, appAdminUser, orgName);

	setupJunction(function(err, result) {
		if (err) {
			logger.error("ums sdt not configured properly!!!");
			throw err;
		}
		else {
			setupDefaultLoginUser(appAdminUser, function(err, result){
				if (err) {
					logger.error("fail to create default user");
					throw err;
				}
				else {
					logger.debug("default user: ", result);
					logger.info("ums sdt configured");
					umsReady = true;
				}
			});
		}
	});
};


function setupJunction(cb) {
	//get list of juctions
	var apiUrl = baseUrl+"api/"+applicationID+"/junctions";
	var options = {
		uri: apiUrl,
		method: 'GET',
		auth: {
			user: userID,
			pass: userPW,
			sendImmediately: true
		},
		json: true,
		strictSSL: false
	};
	
	request(options, function(err, res, results){
		if (err) {
			var errmsg = "err getting list of junctions";
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));
		}
		else {
			logger.debug("list of junctions:", results);
			
			var junctions = (results && results.result) ? results.result : [];
			var found = false;
			for (var i=0; i<junctions.length; i++) {
				if (junctions[i].id == junctionID && 
						junctions[i].instance == instanceID && 
						junctions[i].tenant == tenantID) {
					found = true;
					break;
				}
			}
			
			var method = found ? "PUT" : "POST";
			var postData = {
					"tenantID":tenantID,
					"instanceID":instanceID,
					"junction_point":junctionID,
					"junction_type":"tcp",
					"server_hostname":serverHost,
					"server_port":serverPort,
					"remote_http_header":["iv-user"],
					"scripting_support":"yes", 
					"stateful_junction":"yes", 
					"basic_auth_mode":"supply"
			}

			var options = {
					uri: apiUrl,
					method: method,
					auth: {
						user: userID,
						pass: userPW,
						sendImmediately: true
					},
					json: true,
					body: postData,
					strictSSL: false
			};
			
			logger.debug(options);
			request(options, function(err, res, body){
				if (err) {
					var errmsg = "err seting up junction";
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));
				}
				else if (body && body.message && (body.message.startsWith("UMS-JCT-I") || body.message.startsWith("UMS-JCT-W")) ) {
					logger.debug(body);
					cb && cb(null, body);
				}
				else {
					logger.error("err: junction setup failed:", body);
					var msg = (body && body.message)? body.message : "junction setup failed";
					cb && cb(new Error(msg));
				}
			});
		}
	});
}


function getUserProperties(loginID, cb) {
	var apiUrl = baseUrl+"api/"+applicationID+"/users/"+loginID;
	var options = {
		uri: apiUrl,
		method: 'GET',
		auth: {
			user: userID,
			pass: userPW,
			sendImmediately: true
		},
		json: true,
		strictSSL: false
	};
	
	request(options, function(err, res, user){
		if (err) {
			var errmsg = "error getting user property "+userID;
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));
		}
		else if (!user || !res || !res.statusCode || res.statusCode != 200) {
			var errmsg = "error getting user property "+userID;
			logger.warn(errmsg, user);
			cb && cb(new Error(errmsg));
		}
		else {
			cb && cb(null, user);
		}
	});
}

function createUser(loginID, localID, emailAddress, firstName, lastName, userAccountStatus, locale, role, cb) {
	var apiUrl = baseUrl+"api/"+applicationID+"/users";
	var postData = {
			"tenantID": tenantID,
			"instanceID": instanceID,
			"loginID": loginID,
			"localID" : localID,
			"emailAddress": emailAddress,
			"firstName": firstName,
			"lastName": lastName,
			"userAccountStatus": userAccountStatus,
			"locale": locale,
			"role": role
	}
	var options = {
		uri: apiUrl,
		method: 'POST',
		auth: {
			user: userID,
			pass: userPW,
			sendImmediately: true
		},
		json: true,
		body: postData,
		strictSSL: false
	};
	
	logger.debug(options);
	request(options, function(err, res, body){
		if (err) {
			var errmsg = "createUser request error";
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));
		}
		else if (!body || !res || !res.statusCode || res.statusCode != 201) {
			var errmsg = "error creating user " + userID;
			logger.error(errmsg, body);
			cb && cb(new Error(errmsg));
		}
		else {
			cb && cb(null, body);
		}
	});
}

function changeUserProperties(loginID, localID, emailAddress, firstName, lastName, locale, role, cb) {
	var apiUrl = baseUrl+"api/"+applicationID+"/users/"+loginID;
	var postData = {
			"localID" : localID,
			"emailAddress": emailAddress,
			"firstName": firstName,
			"lastName": lastName,
			"locale": locale,
			"role": role
	}
	var options = {
		uri: apiUrl,
		method: 'PUT',
		auth: {
			user: userID,
			pass: userPW,
			sendImmediately: true
		},
		json: true,
		body: postData,
		strictSSL: false
	};
	
	logger.debug(options);
	request(options, function(err, res, body){
		if (err) {
			var errmsg = "changeUserProperties request error";
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));
		}
		else if (!body || !res || !res.statusCode || res.statusCode != 200) {
			var errmsg = "error changing user properties " + userID;
			logger.error(errmsg, body);
			cb && cb(new Error(errmsg));
		}
		else {
			cb && cb(null, body);
		}
	});
}

//============================================================
// UMS functions
//============================================================

// ready
module.exports.ready = ready;
function ready() {
	return umsReady;
}

// set default user
module.exports.setupDefaultLoginUser = setupDefaultLoginUser;
function setupDefaultLoginUser(appAdminUser, cb) {
	logger.info('setupDefaultUser');
	var userData = {
			id: appAdminUser._name,
			password: dummyPW, 
			enrollId: appAdminUser._name, 
			enrollSecret: appAdminUser._enrollmentSecret, 
			role: "system"
	};	
	
	// get user properties
	getUserProperties(appAdminUser._name, function(err, loginUser){
		if (err) {
			logger.info("default user does not exist; creating a new user: "+ appAdminUser._name);
			createUser(appAdminUser._name, appAdminUser._name, defaultEmail, appAdminUser._name, appAdminUser._name, 'ACTIVE', 'en_US', JSON.stringify(userData), function(err, result){
				if (err) {
					var errmsg = "Error creating a default user";
					logger.error(errmsg, appAdminUser._name);
					cb && cb(new Error(errmsg));
				}
				else {
					logger.info("Successfully created a default user: ", appAdminUser._name);
					cb && cb(null, userData);
				}
			});
		}
		else {
			logger.info("default user already exist ", loginUser);
			var user = {}
			try {
				user = JSON.parse(loginUser.role);
			}
			catch (err) {
				logger.error("Faild to parse login user role :", loginUser.role);
			}
			if (user && user.password) userData.password = user.password;
			
			changeUserProperties(appAdminUser._name, appAdminUser._name, defaultEmail, appAdminUser._name, appAdminUser._name, 'en_US', JSON.stringify(userData), function(err, result){
				if (err) {
					var errmsg = "Error updating a default user's role";
					logger.debug(errmsg, appAdminUser._name);
					cb && cb(new Error(errmsg));
				}
				else {
					logger.info("Successfully updated a default user's role: ", appAdminUser._name);
					cb && cb(null, userData);
				}
			});
		}
	});
}

//update or create login user
//return error if failed, or null if succeed
module.exports.registerLoginUser = registerLoginUser;
function registerLoginUser(id, name, password, enrollId, enrollSecret, role, email, attr, cb ){
//function registerLoginUser(id, name, password, enrollId, enrollSecret, uuid, role, attr_orig, cb ) {
//	var attr = attr_orig;
//	var userData= {
//			id: id,
//			name: name,
//			password: password,
//			role: role,
//			enrollId: enrollId,
//			enrollSecret: enrollSecret,
//			uuid: uuid,
//			attr: attr
//	};
	if (!attr) {
		attr = {};
	}
	var userData = {
			id: id,
			password: password,
			role: role,
			enrollId: enrollId,
			enrollSecret: enrollSecret,
	};
	
	//var email = (attr && attr.email) ? attr.email : defaultEmail;
	
	logger.info('registerLoginUser');
	// get user properties
	getUserProperties(id, function(err, loginUser){
		if (err) {
			logger.info("user does not exist; creating a new user: "+ id);
			createUser(id, id, email, name, name, 'ACTIVE', 'en_US', JSON.stringify(userData), function(err, result){
				if (err) {
					var errmsg = "Error creating a user";
					logger.error(errmsg, id, err);
					cb && cb(new Error(errmsg));
				}
				else {
					logger.info("Successfully created a user: ", result);
					userData["email"] = email;
					userData["data"] = attr;
					cb && cb(null, userData);
				}
			});
		}
		else {
			logger.debug("user exist ", loginUser);
			var user = {}
			try {
				user = JSON.parse(loginUser.role);
			}
			catch (err) {
				logger.error("Faild to parse login user role :", loginUser.role);
			}
//			
//			userData['id'] = id;
//			userData['name'] = name;
//			userData['password'] = password;
//			userData['role'] = role;
//			if (user.id) userData['enrollId'] = user.id;
//			if (user.secret) userData['enrollSecret'] = user.secret;
//			if (user.uuid) userData['uuid'] = user.uuid;
//			userData['attr'] = user;
			
			
			userData['id'] = id;
			userData['password'] = password;
			userData['role'] = role;
			if (user.id) userData['enrollId'] = user.id;
			if (user.secret) userData['enrollSecret'] = user.secret;
			
			changeUserProperties(id, id, email, name, name, 'en_US', JSON.stringify(userData), function(err, result){
				if (err) {
					var errmsg = "Error updating a user";
					logger.error(errmsg, appAdminUser._name);
					cb && cb(new Error(errmsg));
				}
				else {
					logger.debug("Successfully updated a user: ", appAdminUser._name);
					userData["email"] = email;
					userData["data"] = attr;
					cb && cb(null, userData);
				}
			});
		}
	});
}

//return the message
module.exports.changePassword = changePassword;
function changePassword(id, password, token, cb) {
	//send change password reqeust
	//curl --tlsv1.2 -k -u "blckchn_ADMIN:TODO" -H "Accept:application/json" -H "Content-type:application/json" -d '{"password":"TODO", "secureToken":"TODO"}' -X PUT https://10.77.145.163:9811/ums/UserMgmtService/api/blckchn/users/USERID/Password
	cb && cb(null, "to be implemented");
}

// return the login User object
module.exports.getLoginUser = getLoginUser;
function getLoginUser(id, cb) {
	logger.info('getLoginUser');
	// get user properties
	getUserProperties(id, function(err, loginUser){
		if (err) {
			var errmsg = "Got error to getUser";
			logger.warn(errmsg, id);
			cb && cb(new Error(errmsg));
		}
		else {
			logger.info("user exist ", loginUser);
			var userData = {}
			try {
				userData = JSON.parse(loginUser.role);
				cb && cb(null, userData);
				//ums_blockchain.getLoginUser(id, cb);
			}
			catch (err) {
				var errmsg = "ERR: faild to parse login user role";
				logger.error(errmsg, loginUser.role, err);
				cb && cb(new Error(errmsg));
			}
		}
	});
}

// validate userId and password
// for webseal we can't really validate password because it's set as dummyPW
module.exports.validateLoginUser = validateLoginUser;
function validateLoginUser(id, password, data, cb) {
	logger.info('validateLoginUser');
	// get user properties
	getUserProperties(id, function(err, loginUser){
		if (err) {
			var errmsg = "User ID invalid";
			logger.debug(errmsg, id, err);
			cb && cb(new Error(errmsg));
		}
		else {
			logger.info("user exist ", loginUser);
			var userData = {}
			try {
				userData = JSON.parse(loginUser.role);
				if (userData && (userData.password == password || password == dummyPW)) {
					cb && cb(null, userData);
					//ums_blockchain.getLoginUser(id, cb);
				}
				else {
					cb && cb(new Error("ID or password does not match"));
				}
			}
			catch (err) {
				logger.error("Faild to parse login user data :", loginUser.role, err);
				cb && cb(new Error("Faild to validate ID and password"));
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
			var iv_user = headers["iv-user"];
			var iv_server_name = headers["iv_server_name"];
			if (!iv_server_name || !iv_user || (iv_user != basicAuth[0]) || (dummyPW != basicAuth[1])) {
				cb && cb(new Error("Invalid headers"));
			}
			else {
				getLoginUser(iv_user, function(err, user) {;
					if (err) {
						var errmsg = "Error validating header";
						logger.error(errmsg, err);
						cb && cb(new Error(errmsg));
					}
					else if (!user) {
						cb && cb(new Error("User data is empty"));
					} else {
						var timestamp = Math.floor(new Date().getTime() / 1000);
						var token = [timestamp, user.enrollId, user.enrollSecret];
						logger.debug("Validating headers returning token:", token);
						cb && cb(null, token);
					}
				});
			}
		}
	}
	catch (err) {
		var errmsg = "Error validating basic auth";
		logger.error(errmsg, err);
		cb && cb(new Error(errmsg));
	}
}


module.exports.loginUserByHeaders = loginUserByHeaders;
function loginUserByHeaders(req, res, next) {
	var headers = req.headers;
	try {
		var authorization = headers['authorization'];
		if (!authorization) {
			//logout
			logger.warn("No authorization header");
			res.redirect(getLogoutUrl());
		}
		else {
			var b64auth = (authorization || '').split(' ')[1] || ':';
			var basicAuth = new Buffer(b64auth, 'base64').toString().split(':');
			var iv_user = headers["iv-user"];
			var iv_server_name = headers["iv_server_name"];
			if (!iv_server_name || !iv_user || (iv_user != basicAuth[0]) || (dummyPW != basicAuth[1])) {
				logger.error("Invalid headers");
				res.redirect(getLogoutUrl());				
			} else if (iv_user == req.session.username){
				//already logged in
				next();
			} else {
				//login with token timeout = 10 hours
				req.body.username = iv_user;
				req.body.password = dummyPW;
				request_handler.login(req, res, next, getLogoutUrl(), 10*3600);
			}
		}
	}
	catch (err) {
		var errmsg = "Error validating basic auth";
		logger.error(errmsg, err);
		res.redirect(getLogoutUrl());
	}
}



//get default password
module.exports.getDefaultPassword = getDefaultPassword;
function getDefaultPassword(cb) {
	return dummyPW;
}

//get login url
module.exports.getLoginUrl = getLoginUrl;
function getLoginUrl(cb) {
	return "../pkmslogin.form";
	//return "/loginLocal";
}

//get logout url
module.exports.getLogoutUrl = getLogoutUrl;
function getLogoutUrl(cb) {
	return "../pkmslogout";
	//return "/logoutLocal";
}

//get changePassword url
module.exports.getChangePasswordUrl = getChangePasswordUrl;
function getChangePasswordUrl(cb) {
	return "../pkmspassword";
	//return "/changePassworedLocal";
}
