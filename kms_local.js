/*******************************************************************************
 * 
 * 
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 * 
 *******************************************************************************/

 /* 
 * List of ciper
 * [ 'CAST-cbc',
  'aes-128-cbc',
  'aes-128-cbc-hmac-sha1',
  'aes-128-cfb',
  'aes-128-cfb1',
  'aes-128-cfb8',
  'aes-128-ctr',
  'aes-128-ecb',
  'aes-128-gcm',
  'aes-128-ofb',
  'aes-128-xts',
  'aes-192-cbc',
  'aes-192-cfb',
  'aes-192-cfb1',
  'aes-192-cfb8',
  'aes-192-ctr',
  'aes-192-ecb',
  'aes-192-gcm',
  'aes-192-ofb',
  'aes-256-cbc',
  'aes-256-cbc-hmac-sha1',
  'aes-256-cfb',
  'aes-256-cfb1',
  'aes-256-cfb8',
  'aes-256-ctr',
  'aes-256-ecb',
  'aes-256-gcm',
  'aes-256-ofb',
  'aes-256-xts',
  'aes128',
  'aes192',
  'aes256',
  'bf',
  'bf-cbc',
  'bf-cfb',
  'bf-ecb',
  'bf-ofb',
  'blowfish',
  'camellia-128-cbc',
  'camellia-128-cfb',
  'camellia-128-cfb1',
  'camellia-128-cfb8',
  'camellia-128-ecb',
  'camellia-128-ofb',
  'camellia-192-cbc',
  'camellia-192-cfb',
  'camellia-192-cfb1',
  'camellia-192-cfb8',
  'camellia-192-ecb',
  'camellia-192-ofb',
  'camellia-256-cbc',
  'camellia-256-cfb',
  'camellia-256-cfb1',
  'camellia-256-cfb8',
  'camellia-256-ecb',
  'camellia-256-ofb',
  'camellia128',
  'camellia192',
  'camellia256',
  'cast',
  'cast-cbc',
  'cast5-cbc',
  'cast5-cfb',
  'cast5-ecb',
  'cast5-ofb',
  'des',
  'des-cbc',
  'des-cfb',
  'des-cfb1',
  'des-cfb8',
  'des-ecb',
  'des-ede',
  'des-ede-cbc',
  'des-ede-cfb',
  'des-ede-ofb',
  'des-ede3',
  'des-ede3-cbc',
  'des-ede3-cfb',
  'des-ede3-cfb1',
  'des-ede3-cfb8',
  'des-ede3-ofb',
  'des-ofb',
  'des3',
  'desx',
  'desx-cbc',
  'id-aes128-GCM',
  'id-aes192-GCM',
  'id-aes256-GCM',
  'idea',
  'idea-cbc',
  'idea-cfb',
  'idea-ecb',
  'idea-ofb',
  'rc2',
  'rc2-40-cbc',
  'rc2-64-cbc',
  'rc2-cbc',
  'rc2-cfb',
  'rc2-ecb',
  'rc2-ofb',
  'rc4',
  'rc4-40',
  'rc4-hmac-md5',
  'seed',
  'seed-cbc',
  'seed-cfb',
  'seed-ecb',
  'seed-ofb' ]
 */
"use strict";
var { v4: uuidv4 } = require('uuid');
var jsrsa = require('jsrsasign');
var KEYUTIL = jsrsa.KEYUTIL;
var low = require("lowdb");
var FileSync = require('lowdb/adapters/FileSync');
var crypto = require('crypto');
var path = require('path');

var IVLength = 16; // bytes
var AESKeyLength = 32;
var NonceSize = 24;
var db =null;

var TAG = "kms_local.js";
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);


var hfc = require('fabric-client');
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;
var SAVEKEY = false;

module.exports.setup = function() {
    var tmpDir = hfc.getConfigSetting('tmp_dir');
    var keyPath = path.join(tmpDir, 'keys.json');
    var encryptKMS = false;
    var adapter = new FileSync(keyPath, {
        deserialize: (str) => {
            if (encryptKMS) {
                var decipher = crypto.createDecipher('aes192', 'conSenT mAnaGer');
                var decrypted = decipher.update(str, 'hex', 'utf8');
                decrypted += decipher.final('utf8');
                const obj = JSON.parse(decrypted);
                return obj;
            } else {
                const obj = JSON.parse(str);
                return obj;
            }
        },
        serialize: (obj) => {
            if (encryptKMS) {
                var cipher = crypto.createCipher('aes192', 'conSenT mAnaGer');
                var encrypted = cipher.update(str, 'utf8', 'hex');
                encrypted += cipher.final('hex');
                return encrypted;
            } else {
                const str = JSON.stringify(obj);
                return str;
            }
        }
    });
    db = low(adapter);
    logger.info("key manager properly configured");
}

// return a random key for AES
module.exports.getSymKeyAes = getSymKeyAes;
function getSymKeyAes(cb) {
	try {
		var keyBuf = crypto.randomBytes(AESKeyLength);
		var keyBase64 = keyBuf.toString("base64");
		
		//TODO - for testing
		//var keyBase64 = '1hpPhQE9qBmq+3WoXMGiLt1uyf4/8SH7QFGYiby+nAg=';
		
		var uuid = "KEY-" + getUuid();
		var key = {
				keyUuid: uuid,
				KeyAlgorithm: "AES",
				keyType: "SYMMETRIC",
				keyBase64: keyBase64
		}
		
		if (SAVEKEY) {
		  saveKey(key);
		}		
		try {
			cb && cb(null, key);
		}
		catch (err2) {			
			var errmsg = "error running cb in getSymKeyAes";
			logger.error(errmsg, err2);
			cb && cb(new Error(errmsg));
		}
	}
	catch(err) {
		var errmsg = "error getSymKeyAes";
		logger.error(errmsg, err2);
		cb && cb(new Error(errmsg));
	}
}

//get Rsa key pair in PEM format
module.exports.getKeyPairRSA = getKeyPairRSA;
function getKeyPairRSA(cb) {
	try {
		var rsakeys = KEYUTIL.generateKeypair("RSA", 2048);
		var pubpem = KEYUTIL.getPEM(rsakeys.pubKeyObj).replace(/-----BEGIN PUBLIC KEY-----/gi, "").replace(/-----END PUBLIC KEY-----/gi, "").replace(/\r*\n/g,"");
		var prvpem = KEYUTIL.getPEM(rsakeys.prvKeyObj, "PKCS1PRV").replace(/-----BEGIN RSA PRIVATE KEY-----/gi, "").replace(/-----END RSA PRIVATE KEY-----/gi, "").replace(/\r*\n/g,"");
		
		//TODO : for testing
		//var prvpem = "MIIEpQIBAAKCAQEAtYQmMrNr69qqdNT0l1xofA1Uah0ubP709pLMRyrxrh407kVDnXJg4Ij0Gs/7nqcSlTHrcSLLEsgP/tLIFIPADvnmcdgEy2YLVAr5cpwBRZj5rNo5cZ8YJZhfSJGztvTSVvzNCJ0RiuHjIzPlDoBK0JnFOWG9D+pA+fI6PN4GTYceG4SIgWi5resI6HKUOHNDGvy1dOHlHbrvahIVXU10NekTJ9BHLyJnFbQu5jzkrxqrGFdGzWqigr1/TMn8EX8H/iQfxOudJACbW1gt7esH8vu8VqdhaIv4cG7tmWOG9OrkZzji1b/laCuVMndv85kP7rNr8FCfVaFv4RhhpfuWJQIDAQABAoIBAQCAE0hoidTiTB3t5bzXd+p5bWZcoU56tcLeoGHm7VQuCT5LyS+WTngwtjGXIZ1nKnegMeLwpx4mmGdA5DUs1HGVn5qMRWHMqqnfmQa9aXo0Q2YYIrpZg2okTMkeiUAHHeO0YRfCtiEEn7IGyr0aaEdhvL4+aMpgCmfidJnHDNnhpP1ZU8KmmfG9Es/pqReHmGaupAvoQ0XrPRc+a25LUlt93zdh6niC+hivG72EG9Jrym4ceEygy074mVAWvf4uqNG7tqFj0ojlhNVZD+DsvHieUCvfT6NdroALiH0O5/wdWGLEPd+hd4evcwVcMkTzkuuLa0PgHiuToqhLn1fZSvzBAoGBAO3f6vioIvXzi14OaOZavJDi94l0G1ckAFFPiqSnWDTQC5o+b5r0JfvkYF4elZL0G4KoafKlc5mqQufTYcygkb1hOIiZrO7Z5EifOxbIQc3gsfHtKj7uhR4LlrmEOZZKK8ddlslB1hU/9MhqNja0sENRrQP1ZxNT9Mluwq/t4LApAoGBAMNY4TAgr1BW0hT3BOwwBlCRRODSOLre0WbHVDSP/7p/SG8KQHNKCnL1bK4iyAYINZyL1ng7+90C5+omYyRxXUBQGXTajRnjgZWn2xbVbJw2ALPACvRdYj6TKujOZU2y/hdl/mumAorATwslJwgTNUpyZ1jZDaTXr/jjeOryoMWdAoGBAO1+WoLYm88j0Ume6WzTuuCNOsepfIKMFyUXXTz3N0HDVVIydAspJ6NOaEiQEJYf0jepHd59AeWx8Aq1KTe8OMXzgxYfGGGAekNndv9QASMj64W3XC5oxc8xktK2CSjb9MmfzyQw7yVYLXTLVkVYMYOE0FDbeoX5lLRoOUidH2/BAoGBAJ2XKCNxWr0PLW+oT5pSq+V3K//K1+U5N+kYSQAWYxGK+V5LAO+A/aj8AO8CNCdZnBZsYVqh2W/Ulk85JKYTpkzp0X+JiGcoODQJNB/ZkUL79dkMxkmYxFcC1oz1ZJgoG/+4UmV5iXdx6NJu6GwFQuqKHIF6qR0gu1+n8rZngfepAoGAKAoWaur1K1Lb3m2maKdI7M7C5/5//SAibD71bSj9x8aaOprV5ZkKAc7o2vNklKv4uakQdLbi6Zh6JtME/u7l/QjNEUnfN9dZ3Khq/wDV309WafC8ALv/iXMah2ZdxoyTqjPDq4wHFkmFqNTG9B2UUO70Zg6yLM9VdV4/ECoUmQE=";
		//var pubpem = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtYQmMrNr69qqdNT0l1xofA1Uah0ubP709pLMRyrxrh407kVDnXJg4Ij0Gs/7nqcSlTHrcSLLEsgP/tLIFIPADvnmcdgEy2YLVAr5cpwBRZj5rNo5cZ8YJZhfSJGztvTSVvzNCJ0RiuHjIzPlDoBK0JnFOWG9D+pA+fI6PN4GTYceG4SIgWi5resI6HKUOHNDGvy1dOHlHbrvahIVXU10NekTJ9BHLyJnFbQu5jzkrxqrGFdGzWqigr1/TMn8EX8H/iQfxOudJACbW1gt7esH8vu8VqdhaIv4cG7tmWOG9OrkZzji1b/laCuVMndv85kP7rNr8FCfVaFv4RhhpfuWJQIDAQAB"
		
		var uuid1 = "KEY-" + getUuid();
		var prvkey = {
				keyUuid: uuid1,
				keyAlgorithm: "RSA",
				keyType: "PRIVATE",
				keyLength:2048,
				keyBase64: prvpem
		}
		if (SAVEKEY) {
		  saveKey(prvkey);
		}
		var uuid2 = "KEY-" + getUuid();
		var pubkey = {
				keyUuid: uuid2,
				keyAlgorithm: "RSA",
				keyType: "PUBLIC",
				keyLength:2048,
				keyBase64: pubpem
		}
		if (SAVEKEY) {
		  saveKey(pubkey);
		}
		var pair = {
				privateKey: prvkey,
				publicKey: pubkey
		}
		//saveKey(pair);
		
		try {
			cb && cb(null, pair);
		}
		catch (err2) {
			var errmsg = "error running cb in getkeyPairRSA";
			logger.error(errmsg, err2.stack);
		}
		
	}
	catch (err) {
		var errmsg = "error getKeyPairRSA";
		logger.error(errmsg, err);
		cb && cb(new Error(errmsg));
	}

	
}

//get key
module.exports.getKey = getKey;
function getKey(id, cb) {
	try {
		var key = db.get(id).value();
		logger.debug(id,key);
		
		try {
			if (key) {
				cb && cb(null, key);
			}
			else {
				var errmsg = "No key found";
				logger.error(errmsg, err);
				cb && cb(new Error(errmsg));
			}
		}
		catch (err2) {
			var errmsg = "error running cb in getKey";
			logger.error(errmsg, err2);
			cb && cb(new Error(errmsg));
		}
		
	} 
	catch (e) {
		var errmsg = "getKey error";
		logger.error(errmsg, e);
		cb && cb(new Error(errmsg));
	}

}

//delete key
module.exports.deleteKey = deleteKey;
function deleteKey(id, cb) {
	try {
		db.set(id, {}).write();
		try {
			cb && cb(null);
		}
		catch (e2) {
			var errmsg = "deleteKey error";
			logger.error(errmsg, e2);
		}
	} 
	catch (e) {
		var errmsg = "deleteKey error";
		logger.error(errmsg, e);
		cb && cb(new Error(errmsg));
	}
}


// get Uuid
function getUuid() {
	return uuidv4();
}

//save key
function saveKey(key) {
	var uuid = key["keyUuid"];
	logger.debug("write key to DB:", uuid);
	db.set(uuid, key).write();
}

