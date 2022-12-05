/*******************************************************************************
 * 
 * 
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 * 
 *******************************************************************************/

/* global bag */
/* global $ */
"use strict";

//For debugging
var TAG = 'ws_handler.js';
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var hfc = require('fabric-client');
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

var kms = require('../utils/kms.js');

var wss = {};

module.exports.setup = function (pwss) {
	wss = pwss;
};

// Set to true to allow relevant functions to broadcast on success; enables refresh notifications
var allowBroadcast = false;

//send a message, socket might be closed...
function sendMsg(ws, json, data) {
	if (ws) {
		try {
			ws.send(JSON.stringify(json));
			if (allowBroadcast) {
				if (data) {
					if (wss) {
						if (data.type.indexOf('get') == -1) {
							var broadcast_msg = {msg:"broadcast_refresh", data:data};
							wss.broadcast(broadcast_msg);
						}
					}
				}
			}
		}
		catch (err) {
			logger.error(err);
		}
	}
	else {
		logger.warn("Socket closed. message not sent ");
	}
}

function queryTestMsgHandler(ws, data) {
	logger.info('queryTest');
}

function invokeTestMsgHandler(ws, data) {
	logger.info('invokeTest');
}

function signTestMsgHandler(ws, data) {
	logger.info('signTest');
}

function keyTestMsgHandler(ws, data) {
	console.log(TAG, 'keyTest');

	logger.info("==============================================")		
	logger.info("JS TO GO")
	logger.info("==============================================")

	kms.getKeyPairRSA(function(err, keypair) {
		if (err) {
			var errmsg = "error geting keypair";
			logger.error(errmsg, err);
			res.json({msg: errmsg, status: 500});
			res.status(500);
		}
		else {
			kms.getSymKeyAes( function(err, symkey) {
				if (err) {
					var errmsg = "error creating service sym key";
					logger.error(errmsg, err);
					res.json({msg: errmsg, status: 500});
					res.status(500);
				}
				else {
					var serviceKeys = {
							service_public_key: keypair.publicKey.keyBase64,
							service_private_key: keypair.privateKey.keyBase64,
							service_sym_key: symkey.keyBase64,
					};
					logger.info("THE KEYS")
					logger.info(serviceKeys)
				}
			}, data.symkey);
		}
	});

	logger.info("==============================================")		
	logger.info("GO to JS")
	logger.info("==============================================")

	// RSA Key testing 
	var privateKeyB64 = "TODO";
	logger.info("privateKeyB64: ");
	logger.info(privateKeyB64);

	var publicKeyB64 = "TODO";
	logger.info("publicKeyB64: ");
	logger.info(publicKeyB64);

	var symKeyB64 = "TODO";
	logger.info("symKeyB64");
	logger.info(symKeyB64);
	
	var testmsg = "this is a test message 1234 for RSA sign test";
	var encryptedMsg = kms.encryptRSA(testmsg, publicKeyB64);	
	var decryptedMsg = kms.decryptRSA(encryptedMsg, privateKeyB64);
	logger.info("========================================================");
	logger.info("Decrypted RSA message: ");
	logger.info(decryptedMsg);
	logger.info("========================================================");


	// SYM key testing
	var testString2 = "this is a test string for sym key 12324";
	var symKeyBuf = new Buffer(symKeyB64, "base64");
	var testString2B64 = kms.encryptAesSymKey(symKeyBuf, testString2, 'utf8','base64');
	var testString2Hex = new Buffer(testString2B64, 'base64').toString('hex');
	var decryptedMsg2 = kms.decryptAesSymKey(symKeyBuf, testString2B64);
	logger.info("========================================================");
	logger.info("Decrypted sym key message: ");
	logger.info(decryptedMsg2);
	logger.info("========================================================");
}

module.exports.process_msg = process_msg;
function process_msg(ws, data) {

	logger.debug('ws_handler received message:', data);
	// Must have a user to invoke chaincode

	// if (wss) {
	// 	logger.info("flagflag");
	// 	if (data.type.indexOf('get') == -1) {
	// 		logger.info("data type not get");
	// 		var broadcast_msg = {msg:"broadcast_refresh", data:data};
	// 		wss.broadcast(broadcast_msg);
	// 	}
	// }

	if ((!data.user || data.user === '') && data.type != 'registerUser') {
		var errmsg = "user and secret not provided in message";
		logger.error(errmsg);
		sendMsg(ws, {type: "error", error: errmsg});
		return;
	}

	try {
		// Process the message
	
		if (data.type == 'queryTest') {
			queryTestMsgHandler(ws, data);
		}
		else if (data.type == 'invokeTest') {
			invokeTestMsgHandler(ws, data);
		}
		else if (data.type == 'keyTest') {
			keyTestMsgHandler(ws, data);
		}
		else {
			logger.debug("error: unknown message type ", data.type);
		}

		
	} catch (err) {			
		var errmsg = "ws handler message processing error";
		logger.error(errmsg, err);
		/*
		Object.getOwnPropertyNames(err).forEach(function (key) {
			logger.debug("===>", key, err[key]);
			}, err);
		*/
		sendMsg(ws, {type: "error", error: errmsg});
	}


};



