/*******************************************************************************
 * 
 * 
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 * 
 *******************************************************************************/

"use strict";
var { v4: uuidv4 } = require('uuid');
var jsrsa = require('jsrsasign');
var KEYUTIL = jsrsa.KEYUTIL;
var KJUR = jsrsa.KJUR;
var ASN1HEX = jsrsa.ASN1HEX;
//var hfccrypto = require("hfc/lib/crypto");
//var cryptoPrimitives = new hfccrypto.Crypto("SHA3", 256);
var aesjs = require("aes-js");
var crypto = require('crypto');

var IVLength = 16; // bytes
var AESKeyLength = 32;
var NonceSize = 24;
var db =null;

var kms = {}
var TAG = "kms.js";
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var hfc = require('fabric-client');
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

module.exports.setup = function() {
    var kmsmodule = hfc.getConfigSetting('kms_module') || "kms_local.js";
    if (!kmsmodule || kmsmodule === "") {
        kmsmodule = "kms_local.js";
    }
    logger.info("kms_module=", kmsmodule);
    kms = require("./"+kmsmodule);
    kms.setup();
    
    logger.info("key manager properly configured");
}

//============================================================
//UMS interface functions
//============================================================

// return a random key for AES
// key = base64
// cb(err, symkey)
module.exports.getSymKeyAes = getSymKeyAes;
function getSymKeyAes(cb, key) {
    if (key) {
        var aeskey = {
                keyUuid: "",
                KeyAlgorithm: "AES",
                keyType: "SYMMETRIC",
                KeyBase64: key
        }
        cb && cb(null, aeskey);
    }
    else {
        return kms.getSymKeyAes(cb);
    }
}

module.exports.getSymKeyAesPromise = getSymKeyAesPromise;
async function getSymKeyAesPromise(symkey) {
    return new Promise((resolve, reject) => {
        try {
            getSymKeyAes(function(err, key) {
                if (err) {
                    reject(err);
                } else {
                    resolve(key);
                }
            }, symkey);
        } catch (err) {
            reject(err);
        }
    });
}


//get Rsa key pair in PEM format
//prvkey, pubkey = pem
//cb(err, keypair)
module.exports.getKeyPairRSA = getKeyPairRSA;
function getKeyPairRSA(cb, prvkey, pubkey) {
    if (prvkey && pubkey) {
        var pair = {
                privateKey: {
                    keyUuid: "",
                    keyAlgorithm: "RSA",
                    keyType: "PRIVATE",
                    keyBase64: prvkey
                },
                publicKey: {
                    keyUuid: "",
                    keyAlgorithm: "RSA",
                    keyType: "PUBLIC",
                    keyBase64: pubkey
                }
        }
        cb && cb(null, pair);
    }
    else {
        logger.info(kms);
        return kms.getKeyPairRSA(cb);
    }
}


module.exports.getKeyPairRSAPromise = getKeyPairRSAPromise;
async function getKeyPairRSAPromise(prvkey, pubkey) {
    return new Promise((resolve, reject) => {
        try {
            getKeyPairRSA(function(err, key) {
                if (err) {
                    reject(err);
                } else {
                    resolve(key);
                }
            }, prvkey, pubkey);
        } catch (err) {
            reject(err);
        }
    });
}


//get a key with key id
module.exports.getKey = getKey;
function getKey(keyId, cb) {
    return kms.getKey(keyId, cb);
}

module.exports.getKeyPromise = getKeyPromise;
function getKeyPromise(keyId) {
    return new Promise((resolve, reject) => {
        try {
            kms.getKey(keyId, function(err, key) {
                if (err) {
                    reject(err);
                } else {
                    resolve(key);
                }
            });
        } catch (err) {
            reject(err);
        }
    });
}


//delete a key
module.exports.deleteKey = deleteKey;
function deleteKey(keyId, cb) {
    return kms.deleteKey(keyId, cb);
}


//============================================================
//UMS util functions
//============================================================


//returns hex
module.exports.getHash = getHash;
function getHash(bytes) {
    const hash = crypto.createHash('sha256');
    hash.update(bytes);
    return hash.digest('hex');
}


//return a key
module.exports.getRandomKey = getRandomKey;
function getRandomKey() {
    var key = crypto.randomBytes(AESKeyLength);
    return key;
}

//return a iv
module.exports.getRandomIV = getRandomIV;
function getRandomIV() {
    var iv = crypto.randomBytes(IVLength);
    return iv;
}

//return a pw
module.exports.getRandomPassword = getRandomPassword;
function getRandomPassword(len) {
    var pw = crypto.randomBytes(len);
    return pw.toString('base64')
}

module.exports.encryptAesSymKeyToken = encryptAesSymKeyToken;
function encryptAesSymKeyToken(key, text, iv) {
    var buf = Buffer.from(text, "utf8");
    var cipher = crypto.createCipher('aes-256-cbc', key, iv);
    var encrypted = cipher.update(buf, "utf8", "base64");
    encrypted += cipher.final("base64");
    return encrypted;
}

module.exports.decryptAesSymKeyToken = decryptAesSymKeyToken;
function decryptAesSymKeyToken(key, encryptedString, iv) {
    var buf = Buffer.from(encryptedString, "base64");
    var decipher = crypto.createDecipher('aes-256-cbc', key, iv);
    var decrypted = decipher.update(buf, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}


//return encrypted text with symKey
module.exports.encryptAesSymKey = encryptAesSymKey;
function encryptAesSymKey(key, text, fromEnc, toEnc, iv, addIvToCyphertext) {
    if (false !== addIvToCyphertext) addIvToCyphertext = true;
    if (!fromEnc) fromEnc = 'utf8';
    if (!toEnc) toEnc = 'base64';
    var buf = Buffer.from(text, fromEnc);
    if (!iv) {
        iv = getRandomIV();
    }
    var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    var encrypted = cipher.update(buf, fromEnc, "hex");
    encrypted += cipher.final("hex");
    var ivEnc = iv.toString("hex");
    var encryptedHex = addIvToCyphertext ? ivEnc + encrypted : encrypted;
    if (toEnc == "hex") {
        return encryptedHex
    }
    else {
        var encryptedBuf = Buffer.from(encryptedHex, "hex");
        var encryptedResult = encryptedBuf.toString(toEnc);
        return encryptedResult;
    }
}

//return decrypted text
module.exports.decryptAesSymKey = decryptAesSymKey;
function decryptAesSymKey(key, encryptedString, fromEnc, toEnc, iv) {
    if (!fromEnc) fromEnc = 'base64';
    if (!toEnc) toEnc = 'utf8';
    var buf = Buffer.from(encryptedString, fromEnc);
    var buf2 = buf;
    if (!iv) {
        iv =  buf.slice(0,IVLength);
        buf = buf.slice(IVLength, buf.length);
    }
    var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    var decrypted = decipher.update(buf, fromEnc, toEnc);
    decrypted += decipher.final(toEnc);
    return decrypted;
}



//============================================================
//UMS internal functions
//============================================================


function encryptAesSymKey2(key, inputVal, fromEnc, toEnc) {
    if (!fromEnc) fromEnc = 'utf8';
    if (!toEnc) toEnc = 'buf';
    if (fromEnc == 'utf8') {
        //text must be multiple of 16 bytes
        var pad = String.fromCharCode(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
        var padneeded = 16 - (inputVal.length % 16);
        logger.debug(padneeded);
        if (padneeded > 0 && padneeded < 16) {
            inputVal = inputVal + pad.substring(0,padneeded);
        }
    }

    var inputBytes = convertFormat(inputVal, fromEnc, 'buf');
    if (!inputBytes) {
        return null;
    }
    
    var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    var encryptedBytes = aesCbc.encrypt(inputBytes);
    return convertFormat(encryptedBytes, 'buf', toEnc);
}

function decryptAesSymKey2(key, inputVal, fromEnc, toEnc) {
    if (!fromEnc) fromEnc = 'buf';
    if (!toEnc) toEnc = 'utf8';
    
    var inputBytes = convertFormat(inputVal, fromEnc, 'buf');
    if (!inputBytes) {
        return null;
    }
    
    var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    var decryptedBytes = aesCbc.decrypt(inputBytes);
    return convertFormat(decryptedBytes, 'buf', toEnc);
}

// convert format
// enc = 'utf8', 'hex', 'buf', "base64"
// if unknow fronEnc or toEnc, just return null;
function convertFormat(inputVal, fromEnc, toEnc) {
    var inputBytes = null;
    if (fromEnc==toEnc) return inputVal;
    else if (fromEnc == 'buf') inputBytes = inputVal;
    else if (fromEnc == 'hex') inputBytes = aesjs.utils.hex.toBytes(inputVal);
    else if (fromEnc == 'utf8') inputBytes = aesjs.utils.utf8.toBytes(inputVal);
    else return null;

    var outputVal = null;
    if (toEnc == 'buf') return inputBytes;
    else if (toEnc == 'hex') outputVal = aesjs.utils.hex.fromBytes(inputBytes);
    else if (toEnc == 'utf8') outputVal = aesjs.utils.utf8.fromBytes(inputBytes);
    else return null;
    
    return outputVal;
}

// get uuid
module.exports.getUuid = getUuid;
function getUuid() {
    return uuidv4();
}





// encrypt with RsaPublic key return hex encoding using RSA_PKCS1 PADDING
module.exports.encryptRSA = encryptRSA;
function  encryptRSA(toEncryptPlainString, publicKeyPem) {
    if (!publicKeyPem.startsWith("-----BEGIN")) {
        publicKeyPem = "-----BEGIN PUBLIC KEY-----\n"+publicKeyPem+"\n-----END PUBLIC KEY-----\n";
    }
    var pubRSAKeyObj = KEYUTIL.getKey(publicKeyPem);
    var encryptedHexString = KJUR.crypto.Cipher.encrypt(toEncryptPlainString, pubRSAKeyObj);
    return encryptedHexString;
};


// decrypt with Rsa Private key
module.exports.decryptRSA = decryptRSA;
function decryptRSA(toDecryptHexString, privateKeyPem) {
    if (!privateKeyPem.startsWith("-----BEGIN")) {
        privateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n"+privateKeyPem+"\n-----END RSA PRIVATE KEY-----\n";
    }
    var prvRSAKeyObj = KEYUTIL.getKey(privateKeyPem);
    var decryptedString = KJUR.crypto.Cipher.decrypt(toDecryptHexString, prvRSAKeyObj);
    return decryptedString;
};

//Given a certificate byte buffer of the DER-encoded certificate, return
//a PEM-encoded (64 chars/line) string with the appropriate header/footer
module.exports.certToPEM = certToPEM;
function certToPEM(cert) {
    var pem = cert.encode().toString('base64');
    var certStr = "-----BEGIN CERTIFICATE-----\n"
    for (var i = 0; i < pem.length; i++) {
        if ((i>0) && i%64 == 0) certStr += "\n";
        certStr += pem[i]
    }
    certStr += "\n-----END CERTIFICATE-----\n"
    return certStr;
}

//utility function to convert Node buffers to Javascript arraybuffer
function _toArrayBuffer(buffer) {
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return ab;
}

//utility function to convert Javascript arraybuffer to Node buffers
function _toBuffer(ab) {
    var buffer = Buffer.alloc(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        buffer[i] = view[i];
    }
    return buffer;
}

