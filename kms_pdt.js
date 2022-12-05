/*******************************************************************************
 * 
 * 
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 * 
 *******************************************************************************/

/* 
 * Examples
 * 
ssh -i id_rsa.txt -N root@9.220.104.253 -L 9443:10.47.120.144:9443
10.47.120.144:9443

curl -v -k -H "Content-type: application/json" -X POST -d '{"cn":"cmadmin","ou":"admin","o":"consent-management", "password":"TODO"}' https://localhost:9443/km-web/rest/alpha/login
{"authToken":"TODO"}

curl -v -k -H "Authorization: Bearer TODO" -H "Content-type: application/json" -X POST -d '{"keyAccessGroupNames": ["consent-manager"], "keyType": "ASYMMETRIC", "keyAlgorithm": "RSA", "keyLength": 2048}' https://localhost:9443/km-web/rest/alpha/keys
[{"keyUuid":"TODO","keyType":"PRIVATE"},{"keyUuid":"TODO","keyType":"PUBLIC"}]


curl -v -k -H "Authorization: Bearer TODO" -H "Content-type: application/json" -X POST -d '{"keyAccessGroupNames": ["consent-manager"], "keyType": "SYMMETRIC", "keyAlgorithm": "AES", "keyLength": 256}' https://localhost:9443/km-web/rest/alpha/keys
[{"keyUuid":"TODO","keyType":"SYMMETRIC"}]

curl -v -k -H "Authorization: Bearer TODO" -H "Content-type: application/json" -X GET https://localhost:9443/km-web/rest/alpha/keys/TODO
RSA private
{"keyUuid":"TODO","keyAlgorithm":"RSA","keyLength":2048,"keyType":"PRIVATE","relatedKeyUuid":"TODO","keyBase64":"TODO","ivBase64":null,"timestampCreate":1490991954741,"timestampUpdate":1490991954741,"userUuidCreate":"TODO","userUuidUpdate":"TODO"}

curl -v -k -H "Authorization: Bearer TODO" -H "Content-type: application/json" -X GET https://localhost:9443/km-web/rest/alpha/keys/TODO
RSA public
{"keyUuid":"TODO","keyAlgorithm":"RSA","keyLength":2048,"keyType":"PUBLIC","relatedKeyUuid":"TODO","keyBase64":"TODO","ivBase64":null,"timestampCreate":1490991954741,"timestampUpdate":1490991954741,"userUuidCreate":"TODO","userUuidUpdate":"TODO"}


curl -v -k -H "Authorization: Bearer TODO" -H "Content-type: application/json" -X GET https://localhost:9443/km-web/rest/alpha/keys/TODO
AES
{"keyUuid":"TODO","keyAlgorithm":"AES","keyLength":256,"keyType":"SYMMETRIC","relatedKeyUuid":null,"keyBase64":"TODO","ivBase64":"TODO","timestampCreate":1490992216198,"timestampUpdate":1490992216198,"userUuidCreate":"TODO","userUuidUpdate":"TODO"}

curl -v -k -H "Authorization: Bearer TODO" -H "Content-type: application/json" -X DELETE https://localhost:9443/km-web/rest/alpha/keys/TODO
 
error return:
[{"messageType":"ERROR","message":"The entity [TODO] is not found."}]
 */

"use strict";
var request = require('request');

var TAG = "kms_pdt.js";
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var hfc = require('fabric-client');
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

var doInitTest = false;

var host = "https://10.47.120.144:9443";
//var host = "https://localhost:9443";
var cn = "cmadmin";
var ou = "admin";
var o = "consent-management";
var password = "TODO";
var kagn = "consent-manager";

module.exports.setup = function(p_host, p_cn, p_ou, p_o, p_password, p_kagn) {
	if (p_host) host = p_host;
	if (p_cn) cn = p_cn;
	if (p_ou) ou = p_ou;
	if (p_o) o = p_o;
	if (p_password) password = p_password;
	if (p_kagn) kagn = p_kagn;
	
	logger.debug("host=", host);
	logger.debug("cn=", cn);
	logger.debug("ou=", ou);
	logger.debug("o=", o);
	logger.debug("password=", password);
	logger.debug("keyAccessGroupName=", kagn);
	
	getToken(null, function(err, token){
		if (err) {
			var errmsg = 'KMS login error';
			logger.error(errmsg, err);			
			throw err;
		}
		else {
			logger.debug("getToken:",token);
			if (!doInitTest) {
				logger.info("KMS properly configured");
			}
			else {
				//do all function test
				getSymKeyAes(function(err, key){
					if (err) {
						var errmsg = "getSymAes error";
						logger.error(errmsg, err);	
						throw err;
					}
					else {
						logger.debug("getSymAes: ", key);
						deleteKey(key.keyUuid, function(err){
							if (err) {
								var errmsg = "deleteKey error";
								logger.error(errmsg, err);	
								throw err;
							}
							else {
								logger.debug("key deleted:", key.keyUuid);
								getKeyPairRSA(function(err, pair){
									if (err) {
										var errmsg = "getKeyPairRSA error";
										logger.error(errmsg, err);	
										throw err;
									}
									else {
										logger.debug("getKeyPairRSA:", pair);
										delete(pair.privateKey.keyUuid);
										delete(pair.publicKey.keyUuid);
	
										logger.info("KMS properly configured");
									}
								},token);
							}
						}, token);
					}
				}, token);
			}
		}
	});
}

// return a random key for AES
module.exports.getSymKeyAes = getSymKeyAes;
function getSymKeyAes(cb, prevToken) {
	getToken(prevToken, function(err, token){
		if (err) {
			var errmsg = "getToken getSymKeyAes error";
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));			
		}
		else {
			var postData = {"keyAccessGroupNames": [kagn], "keyType": "SYMMETRIC", "keyAlgorithm": "AES", "keyLength": 256};
			var options = {
				uri: host + '/km-web/rest/alpha/keys',
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': 'Bearer '+token
				},
				json: true,
				body: postData,
				strictSSL: false
			};
		
			request(options, function(err, res, body){
				if (err) {
					var errmsg = "err getSymKeyAes";
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));		
				}
				else if (body && body.length == 1 && "ERROR" == body[0].messageType) {
					logger.debug(body);
					
					var errmsg = body.message;
					logger.error(errmsg);
					cb && cb(new Error(errmsg));
				}
				else if (body && body.length==1 && body[0].keyUuid) {
					var uuid = body[0].keyUuid;
					return getKey(uuid, cb, token);
				}
				else {
					var errmsg = "err getSymkeyAes: no key or invalid key";
					logger.error(errmsg, body);
					cb && cb(new Error(errmsg));
				}
			});
		}
	});
}

//get Rsa key pair in PEM format
module.exports.getKeyPairRSA = getKeyPairRSA;
function getKeyPairRSA(cb, prevToken) {
	getToken(prevToken, function(err, token){
		if (err) {
			var errmsg = "getToken getKeyPairRSA error";
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));
		}
		else {
			var postData = {"keyAccessGroupNames": [kagn], "keyType": "ASYMMETRIC", "keyAlgorithm": "RSA", "keyLength": 2048};
			var options = {
				uri: host + '/km-web/rest/alpha/keys',
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': 'Bearer '+token
				},
				json: true,
				body: postData,
				strictSSL: false
			};
		
			//get RSA key pair
			request(options, function(err, res, body){
				if (err) {
					var errmsg = "err getKeyPairRSA";
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));
				}
				else if (body && body.length == 1 && "ERROR" == body[0].messageType) {
					logger.debug(body);
					
					var errmsg = body.message;
					logger.error(errmsg);
					cb && cb(new Error(errmsg));
				}
				else if (!body || body.length != 2 || !body[0].keyUuid || !body[1].keyUuid) {
					
					var errmsg = "no key or invalid key";
					logger.error(errmsg);
					cb && cb(new Error(errmsg));
				}
				else {
					
					var uuid1 = body[0].keyUuid;
					var uuid2 = body[1].keyUuid;
					//get the first key
					getKey(uuid1, function(err, key){
						
						if (err) {
							var errmsg = "getKey uuid1 error";
							logger.error(errmsg, err);
							cb && cb(new Error(errmsg));
						}
						else {
							var pair = {};
							if (key.keyType == "PRIVATE") {
								pair["privateKey"] = key;
							}
							else {
								pair["publicKey"] = key;
							}
							
							//get the second key
							getKey(uuid2, function(err, key2){
								if (err) {
									var errmsg = "getKey uuid2 error";
									logger.error(errmsg, err);
									cb && cb(new Error(errmsg));
								}
								else {
									if (key2.keyType == "PRIVATE") {
										pair["privateKey"] = key2;
									}
									else {
										pair["publicKey"] = key2;
									}
									cb && cb(null, pair);
								}
							}, token);
						}
					}, token);
				}
			});
		}
	});
}

//get key
module.exports.getKey = getKey;
function getKey(id, cb, prevToken) {
	getToken(prevToken, function(err, token){
		if (err) {
			var errmsg = "getToken getKey error";
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));
		}
		else {
			var options = {
				uri: host + '/km-web/rest/alpha/keys/'+id,
				method: 'GET',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': 'Bearer '+token
				},
				json: true,
				strictSSL: false
			};
		
			logger.debug("trying to get key with id=", id);
			request(options, function(err, res, body){
				if (err) {
					var errmsg = "err getKey with id="+id;
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));
				}
				else if (body && body.keyUuid) {
					logger.info("got key:", body);
					cb && cb(null, body);
				}
				else {
					var errmsg = body.message;
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));
				}
			});
		}
	});
}

//delete key
module.exports.deleteKey = deleteKey;
function deleteKey(id, cb, prevToken) {
	getToken(prevToken, function(err, token){
		if (err) {
			var errmsg = "getToken deleteKey err";
			logger.error(errmsg, err);
			cb && cb(new Error(errmsg));
		}
		else {
			var options = {
				uri: host + '/km-web/rest/alpha/keys/'+id,
				method: 'DELETE',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': 'Bearer '+token
				},
				json: true,
				strictSSL: false
			};
		
			request(options, function(err, res, body){
				if (err) {
					var errmsg = "err deleteKey with id="+id;
					logger.error(errmsg, err);
					cb && cb(new Error(errmsg));
				}
				else if (body && body.length == 1 && "ERROR" == body[0].messageType) {
					logger.debug(body);
					
					var errmsg = body.message;
					logger.error(errmsg);
					cb && cb(new Error(errmsg));
				}
				else {
					logger.info("deleteKey:", id);
					cb && cb(null);
				}
			});
		}
	});
}


// return prevToken if provided, or call login to get a new token
function getToken(prevToken, cb) {
	if (prevToken) {
		cb && cb(null, prevToken);
	}
	else {
		var postData = {"cn":cn,"ou":ou,"o":o, "password":password};
		var options = {
			uri: host + '/km-web/rest/alpha/login',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			json: true,
			body: postData,
			strictSSL: false
		};
	
		request(options, function(err, res, body){
			if (err) {
				var errmsg = "err getToken";
				logger.error(errmsg);
				cb && cb(new Error(errmsg));
			}
			else if (!body || !body.authToken) {
				var errmsg = "no authToken";
				logger.error(errmsg);
				cb && cb(new Error(errmsg));
			}
			else {
				cb && cb(null, body.authToken);
			}
		});
	}
}

