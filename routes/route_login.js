/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

/*
 * Hadling login
 */

var crypto = require('crypto');
var hfc = require('fabric-client');

// Load our modules.
var user_manager = require('../user_manager.js');
var chain_helper = require('../chain_helper.js');
var ums = require('../ums.js');
var kms = require('../kms.js');

// original API handler is here. Transform original api handler to common handler
var req_handler = require('../request_handler.js');

// Use tags to make logs easier to find
var TAG = "route_login.js";
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

const unauthorizedError = 401;

// ============================================================================================================================
// Home
// ============================================================================================================================

// 1. if path is /login or /mfa skip authentication,
// 2. check token
// 3. if authorization (basic auth) exist in headers, remove token in session
// 4. check token in session
// 5. check headers
// 6. apilogin (require same headers as login) - basic auth first and then headers
exports.login = login;
function login(req, res, next) {
    // do logging
    logger.info(req.method, req.originalUrl);
    logger.debug(req.headers);
    logger.debug(req.session);

    //clear header
    req.headers["enroll-id"] = null;
    req.headers["enroll-secret"] = null;
    req.headers["ca-org"] = null;
    req.headers["channel"] = null;

    // check token
    var token = req.headers["token"];
    if (token) {
        req.session["token"] = null;
        logger.info("got token from header");
    } else {
        // if basic auth, remove token from session
        var auth = req.headers.authorization;
        if (auth) {
            req.session["token"] = null;
            logger.info("basic auth enabled");
        }
        // check token in session
        token = req.session["token"];
        if (token) {
            logger.info("got token from session");
        }
    }

    if (req.path == "/sign") {
        //sign doesn't need to verify signature
        next();

    } else if (req.path.startsWith("/mfa")) {
        //mfa doesn't need to login
        next();
        
    } else if (req.path == "/login") {
        //login doesn't need to authenticate, but
        //still need to verify signature
        var login_info = getLoginInfo(req);
        var enrollId = login_info["id"];
        var enrollSecret = login_info["password"];
        var caOrg = login_info["org"];
        verifySignatureAndNext(enrollId, enrollSecret, caOrg, req, res, next);
        
    } else {
        //authenticate token
        user_manager.validateLoginToken(token, function (err, tokenList) {
            if (err) {
                if (token) {
                    logger.warn("Login token failed");
                    logger.debug(err)
                }

                //authenticate by headers (ums specific)
                user_manager.validateUserByHeaders(req.headers, function (err, tokenList) {
                    if (err) {
                        logger.warn("Authentication by Headers failed");
                        logger.debug(err);

                        //authenticate by apilogin (same as /login parameters)
                        apiLogin(req, res, next);

                    } else {
                        // Authentication by Header validated
                        let enrollId = tokenList && tokenList[1] ? tokenList[1] : "";
                        let enrollSecret = tokenList && tokenList[2] ? tokenList[2] : "";
                        let caOrg = tokenList && tokenList[3] ? tokenList[3] : "";
                        let channel = tokenList && tokenList[4] ? tokenList[4] : "";
                        req.headers["enroll-id"] = enrollId;
                        req.headers["enroll-secret"] = enrollSecret;
                        req.headers["ca-org"] = caOrg;
                        req.headers["channel"] = channel;

                        logger.info("Authentication by Headers validated for", enrollId, caOrg, channel);
                        verifySignatureAndNext(enrollId, enrollSecret, caOrg, req, res, next);
                    }
                });

            } else {
                // login token validated
                let enrollId = tokenList && tokenList[1] ? tokenList[1] : "";
                let enrollSecret = tokenList && tokenList[2] ? tokenList[2] : "";
                let caOrg = tokenList && tokenList[3] ? tokenList[3] : "";
                let channel = tokenList && tokenList[4] ? tokenList[4] : "";
                req.headers["enroll-id"] = enrollId;
                req.headers["enroll-secret"] = enrollSecret;
                req.headers["ca-org"] = caOrg;
                req.headers["channel"] = channel;

                logger.info("login token validated for", enrollId, caOrg, channel);
                verifySignatureAndNext(enrollId, enrollSecret, caOrg, req, res, next);
            }
        });
    }
}

//this function checks signature and checks if payload is encrypted
function verifySignatureAndNext(username, secret, org, req, res, next) {
    let verify_signature = req_handler.solutionConfig["verify_user_signature"];
    let disable_verify_signature = req_handler.solutionConfig["disable_verify_user_signature_for_localhost"];
    let disable_verify_signature_no_key = req_handler.solutionConfig["skip_verify_user_signature_if_no_key_found"];
    //don't need to signature if request is from local host
    if (verify_signature && disable_verify_signature) {
        let host = req.get('host');
        if (host.startsWith("localhost")) {
            verify_signature = false;
            logger.info("verify signature disabled for localhost:", host);
        }
    }

    //decrypt payload if payload is encrypted
    if (req.body && req.body._key_ && req.body._data_) {
        logger.debug("Decrypting payload");
        //decrypt key -- it should be encrypted with the public key
        let prvkey = req_handler.solutionConfig["app_admin"]["private_key"];
        let keyHex = Buffer.from(req.body._key_, "base64").toString("hex");
        let symKeyB64 = kms.decryptRSA(keyHex, prvkey);
        let symKey = Buffer.from(symKeyB64, "base64");
        let iv = null;
        if (req.body._iv_) {
            iv = Buffer.from(req.body._iv_, "base64");
        }
        decBody = kms.decryptAesSymKey(symKey, req.body._data_, "base64", "utf8", iv);
        try {
            let bodyJson = JSON.parse(decBody);
            req.body = bodyJson;
        } catch (err) {
            logger.error("Decrypting payload failed:", err);
        }
    }

    //verify signature
    if (!verify_signature) {
        next();
    } else {
        var signature = req.headers["signature"];

        if (!signature) {
            var errmsg = "signature header is missing";
            logger.error(errmsg);
            res.status(unauthorizedError).json({ msg: "Invalid signature:" + errmsg, status: unauthorizedError });
        } else {

            let signatureList = signature.split(":");
            let signAlgorithm = "";
            if (signatureList.length == 2) {
                signAlgorithm = signatureList[1];
            }

            const url = req.originalUrl;
            var message = username + url;
            var method = req.method;
            let payload = "";
            if (method == "POST" || method == "PUT") {
                payload = req.body;
                if (typeof payload === 'string' || payload instanceof String) {
                    message = message + payload;
                } else {
                    payload = JSON.stringify(payload);
                    message = message + payload;
                }
            }

            if (signAlgorithm == "solution-ui") {
                // UI signature verification
                let verifyKey = req_handler.solutionConfig["ui_verify_key"];
                //verify signature
                let verified = verifySignature(verifyKey, signature, message);
                if (!verified) {
                    var errmsg = "UI signature verification failed";
                    logger.error(errmsg);
                    res.status(unauthorizedError).json({ msg: "Invalid signature:" + errmsg, status: unauthorizedError });
                } else {
                    logger.info("UI Signature verification succeeded");
                    next();
                }


            } else {
                
                let attrs = [{ name: "id" }, { name: "verifykey" }];
                chain_helper.getUserAttributes(username, secret, attrs, org).then((amap) => {
                    if (amap && amap["verifykey"] && amap["verifykey"] != user_manager.NO_VERIFY_KEY) {
                        let verifyKey = amap["verifykey"];
                        //verify signature
                        let verified = verifySignature(verifyKey, signature, message);
                        if (!verified) {
                            var errmsg = "Signature verification failed";
                            logger.error(errmsg);
                            res.status(unauthorizedError).json({ msg: "Invalid signature:" + errmsg, status: unauthorizedError });
                        } else {
                            logger.info("Signature verification succeeded");
                            next();
                        }

                    } else {
                        var errmsg = "Verify key not found on the CA server";
                        if (disable_verify_signature_no_key) {
                            logger.warn(errmsg + ":", "skiping signature verfication");
                            next();
                        } else {
                            logger.error(errmsg);
                            res.status(unauthorizedError).json({ msg: "Invalid signature:" + errmsg, status: unauthorizedError });
                        }
                    }
                }).catch((err) => {
                    var errmsg = "Invalid signature";
                    logger.error(errmsg, err);
                    res.status(unauthorizedError).json({ msg: "Invalid signature:" + errmsg, status: unauthorizedError });
                });
            }

        }

    }
}

function verifySignature(verifyKey, signature, message) {
    if (!hasPemHeader(verifyKey)) {
        verifyKey = "-----BEGIN PUBLIC KEY-----\n" + verifyKey + "\n-----END PUBLIC KEY-----\n";
    }
    //verify signature
    signatureList = signature.split(":");
    let algorithm = "sha256";
    if (signatureList.length == 2) {
        if (signatureList[1] != "solution-ui") {
            algorithm = signatureList[1];
        }
        signature = signatureList[0];
    }

    const verifier = crypto.createVerify(algorithm);
    verifier.update(message);
    verifier.end();
    let verified = verifier.verify(verifyKey, signature, "base64");
    return verified;
}

function apiLogin(req, res, next) {
    var login_info = getLoginInfo(req);
    var id = login_info["id"];
    var password = login_info["password"];
    var channel = login_info["channel"];
    var org = login_info["org"];

    if (!id || !password || !org || !channel) {
        logger.error("API Login failed");
        res.status(unauthorizedError).json({ msg: "Unauthorized.", status: unauthorizedError });
    } else {
        let user_data = {
            org: org,
            channel: channel
        };
        ums.validateLoginUser(id, password, user_data, function (err, user) {
            if (err) {
                logger.error("API Login failed:", err);
                res.status(unauthorizedError).json({ msg: "Unauthorized:" + err, status: unauthorizedError });
            } else {
                // User successfully login via API Login
                req.headers["enroll-id"] = user.enrollId;
                req.headers["enroll-secret"] = user.enrollSecret;
                req.headers["ca-org"] = user.caOrg;
                req.headers["channel"] = user.channel;

                logger.info("API Login successed for", user.enrollId, user.caOrg, user.channel);
                verifySignatureAndNext(user.enrollId, user.enrollSecret, user.caOrg, req, res, next);
            }
        });
    }
}

exports.getLoginInfo = getLoginInfo;
function getLoginInfo(req) {
    var b64auth = (req.headers.authorization || '').split(' ')[1] || ':';
    var basicAuth = new Buffer(b64auth, 'base64').toString().split(':');
    var ba_id = null;
    var ba_org = null;
    var ba_channel = null;
    var ba_pass = null;
    if (basicAuth[0]) {
        let val1 = basicAuth[0].split('/');
        if (val1.length >= 1) {
            ba_id = val1[0];
        }
        if (val1.length >= 2) {
            ba_org = val1[1];
        }
        if (val1.length >= 3) {
            ba_channel = val1[2];
        }
    }
    if (basicAuth[1]) {
        ba_pass = basicAuth[1];
    }

    //use user-id and password header if basicauth header does not exist
    var id = ba_id ? ba_id : req.headers["user-id"];
    var password = ba_pass ? ba_pass : req.headers["password"];
    var channel = ba_channel ? ba_channel : req.headers["login-channel"] ? req.headers["login-channel"] : Object.keys(req_handler.solutionConfig["channels"])[0];
    var org = ba_org ? ba_org : req.headers["login-org"];

    var user_info = {
        id: id,
        password: password,
        channel: channel,
        org: org
    };
    return user_info;
}


function parseQuery(querystring) {
    // remove any preceding url and split
    querystring = querystring.substring(querystring.indexOf('?') + 1).split('&');
    var params = {},
        pair, d = decodeURIComponent;
    // march and parse
    for (var i = querystring.length - 1; i >= 0; i--) {
        pair = querystring[i].split('=');
        params[d(pair[0])] = d(pair[1] || '');
    }
    return params;
}

//returns client ip
function getClientIp(req) {
    let ip = (req.headers['x-forwarded-for'] || '').split(',').pop() ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        (req.connection.socket ? req.connection.socket.remoteAddress : null);
    return ip;
}

//check if key already has header or not
function hasPemHeader(key) {
    return key.startsWith("-----BEGIN");
}

