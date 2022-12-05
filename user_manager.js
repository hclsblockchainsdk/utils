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
var ums = require('../utils/ums.js');
var helper = require('../utils/chain_helper.js');
var User = require('fabric-client/lib/User.js');
var hfc = require('fabric-client');
var appIDHelper = require('../utils/ums_app_id_helper.js');
const { getDeIdentifiedPii } = require('common-utils/deIdentifierUtils/deIdentifierService');

const deIdentifierConfig = hfc.getConfigSetting('de_identifier');
const isDeIdentifierServiceEnabled = deIdentifierConfig && deIdentifierConfig.enabled;

// Use a tag to make logs easier to find
var TAG = "user_manager.js";
const CaUserRoles = {
    Client: "client",
    Peer: "peer",
    Admin: "admin",
    Orderer: "orderer"
};
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

var serverKey = null;
var serverIv = null;
var NO_VERIFY_KEY = "__NO_VERIFY_KEY__";

module.exports.NO_VERIFY_KEY = NO_VERIFY_KEY;
module.exports.setup = function () {

    //generate serverKey for generating token
    const defaultSolutionConfig = helper.solutionConfig();
    const omrSolutionConfig = defaultSolutionConfig['solutions']['owner-mediated-records'];
    if (omrSolutionConfig.tokenSecretKey && omrSolutionConfig.tokenSecretKeyIV) {
        serverKey = omrSolutionConfig.tokenSecretKey;
        serverIv = omrSolutionConfig.tokenSecretKeyIV;
    } else {
        serverKey = kms.getRandomKey();
        serverIv = kms.getRandomIV();
    }
    logger.debug( "Serverkey for access token generated");
    // let's register the user

};

module.exports.getRegistrarInfo = getRegistrarInfo;
function getRegistrarInfo() {
    return adminUser;
}

module.exports.getAppAdminInfo = getAppAdminInfo;
function getAppAdminInfo() {
    return appAdminUser;
}
module.exports.getAppAdminId = getAppAdminId;
function getAppAdminId() {
    return appAdminUser.getName();
}

module.exports.getAppAdminSecret = getAppAdminSecret;
function getAppAdminSecret() {
    return appAdminUser._enrollmentSecret;
}

/*
 *  login user
 *
 *
var loginUser = {
        id: user.id,
        name: user.name,
        password: user.password,
        role: user.role,
        enrollId: user.id,
        enrollSecret: user.secret,
        uuid: user.uuid,
        attr: user
}


type User struct {
    Id       string `json:"id"`
    Name     string `json:"name"`
    Org      string `json:"org"`
    Role     string `json:"role"`
    Service  string `json:"service"`
    Source   string `json:"source"`
    Ref      string `json:"ref"`
    Secret   string `json:"secret"`
    Password string `json:"password"`
    Pubkey   string `json:"pubkey"`
    Prvkey   string `json:"prvkey"`
    Symkey   string `json:"symkey"`
    Uuid     string `json:"uuid"`
}

 */


// this function registers user on Blockchain (CA)
// verifyKey, pubKey, prvKey, symKey = base64 string (optional)
// failIfAlreadyRegistered. when it is true fail if user is already registered.
// add email as it is required in multi factor authentication.

// return [user, enrollment]
module.exports.registerUser = registerUser;
async function registerUser(userid, userSecret, role, caOrg, email, verifyKey, prvKey, pubKey, symKey, failIfAlreadyRegistered) {
    logger.info("Register User : "+userid+" for "+ caOrg);

    // user is checked by the following order
    // 1. check if user exist
    // 2. try register a new user

    try {
        let user = null;
        let enrollmentSecret = null;
        let attrList = [];

        let adminClient = await helper.getAdminClientForOrg(caOrg);

        //get client & caClient & admin
        let adminCaClient = adminClient.getCertificateAuthority();
        let adminUser = await adminClient.getUserContext();

        // 1. check if user exists
        try {
            user = await helper.getRegisteredUser(userid, userSecret, caOrg);
            if (user) {
                enrollmentSecret = userSecret;
                logger.info("User is already registered: "+userid);
            }
        } catch(err) {
            logger.debug("User is not already registered:" + err);
        }

        if (failIfAlreadyRegistered && user) {
            throw new Error("User is already registered: "+userid);
        }

        // 2. user not found, let's register the user
        if (!user) {
            logger.info('\''+userid+'\' not found; Try register.');

            // generate key
            let keypair = await kms.getKeyPairRSAPromise(prvKey, pubKey);
            let symKeyObj = await kms.getSymKeyAesPromise(symKey);

            let pubkey = keypair.publicKey.keyBase64;
            let prvkey = keypair.privateKey.keyBase64;
            let symkey = symKeyObj.keyBase64;

            //verifyKey = verifyKey ? verifyKey : NO_VERIFY_KEY;

            // save attributes
            attrList.push( {name: "id", value: userid} );
            attrList.push( {name: "role", value: role} );
            attrList.push( {name: "verifykey", value: verifyKey} );
            attrList.push( {name: "prvkey", value: prvkey} );
            attrList.push( {name: "pubkey", value: pubkey} );
            attrList.push( {name: "symkey", value: symkey} );
            try {
                enrollmentSecret = await helper.registerUser(adminCaClient, adminUser, userid, userSecret, CaUserRoles.Client, caOrg, "", attrList);
                logger.info(userid + ' registered successfully');
            } catch (err) {
                logger.error("Fail to register user to CA:", err);
                if (err.toString().includes("already registered")) {
                    throw new Error("User is already registered; Please provide correct secret for the user");
                } else {
                    throw new Error("Failed to register user to CA");
                }
            }
        } else {
            let attr_reqs = [];
            attr_reqs.push( {name: "id"} );
            attr_reqs.push( {name: "role"} );
            attr_reqs.push( {name: "verifykey"} );
            attr_reqs.push( {name: "prvkey"} );
            attr_reqs.push( {name: "pubkey"} );
            attr_reqs.push( {name: "symkey"} );
            let amap = await helper.getUserAttributes(userid, userSecret, attr_reqs, caOrg);
            attrList.push( {name: "id", value: amap["id"]} );
            attrList.push( {name: "role", value: amap["role"]} );
            attrList.push( {name: "verifykey", value: amap["verifykey"]} );
            attrList.push( {name: "prvkey", value: amap["prvkey"]} );
            attrList.push( {name: "pubkey", value: amap["pubkey"]} );
            attrList.push( {name: "symkey", value: amap["symkey"]} );
        }

        // registerLoginUser in ums. It could be app id depending on ums configuration.
        if(ums.getUmsModule() != "ums_ca.js") {
            let channelName = Object.keys(helper.channelConfigs())[0];
            attrList.push({name: "caOrg", value: caOrg});
            attrList.push({name: "channel", value: channelName});
            ums.registerLoginUser(userid, "", userSecret, userid, enrollmentSecret, role, email, attrList, function(err, result){
                if(err) {
                    logger.error("Failed to register a login user:", err);
                    throw new Error("Failed to register a user: "+err.toString());
                } else {
                    logger.info('login user '+ userid + ' registered successfully.');
                }
            });
        }
        return attrList;
    } catch (err) {
        logger.error("Failed to register a user ", err);
        throw new Error("Failed to register a user: "+err.toString());
    }
}

//login token = [expire_timestamp, id, secret, org, channel]
module.exports.getLoginToken = getLoginToken;
function getLoginToken(id, password, data, cb, timeoutsec) {
    // TODO: this code is for owner-mediated-records solution
    // and will be removed in scope of WHHUNSDK-311
    const defaultSolutionConfig = helper.solutionConfig();
    const omrSolutionConfig = defaultSolutionConfig['solutions']['owner-mediated-records'];
    const omrAdminUser = omrSolutionConfig && omrSolutionConfig['app_admin']['username'];

    // User ID is PII/PHI data. We cannot store PII/PHI data in chaincode.
    // To retrieve login token by User ID from chaincode
    // we need to use de-identified User ID.
    // For any user except app Admin we need to get de-identified User ID.
    if (isDeIdentifierServiceEnabled && id !== omrAdminUser) {
        getDeIdentifiedPii(id).then(deIdentifiedId => {
            getLoginTokenFromUms(deIdentifiedId, password, data, cb, timeoutsec)
        }).catch(e => {
            const message = 'Cannot get login token.';
            logger.error(message, e);
            cb && cb(new Error(message + e));
        });
    } else {
        getLoginTokenFromUms(id, password, data, cb, timeoutsec);
    }
}

function getLoginTokenFromUms(id, password, data, cb, timeoutsec) {
    logger.info("trying to get login token for: " + id);
    try {
        ums.validateLoginUser(id, password, data, function(err, user) {
            if (err) {
                var errmsg = "Invalid password or user validation failed";
                logger.error(errmsg, err);
                cb && cb(new Error(errmsg));
            }
            else {
                if (!timeoutsec || timeoutsec < 0) {
                    timeoutsec = parseInt(hfc.getConfigSetting('login_token_timeout_sec'));
                }
                var timestamp = Math.floor(new Date().getTime() / 1000) + timeoutsec;
                var token = [timestamp, user.enrollId, user.enrollSecret, user.caOrg, user.channel];
                var tokenString = JSON.stringify(token);
                var tokenHex = kms.encryptAesSymKeyToken(serverKey, tokenString, serverIv);
                if (!tokenHex) {
                    logger.debug( "failed to get token:", tokenString);
                    cb && cb(new Error("failed to get token"));
                }
                else {
                    logger.debug("successfully got token:", tokenHex);
                    cb && cb(null, tokenHex, user);
                }
            }
        });
    }
    catch (err) {
        let errmsg = "error getting token";
        logger.error(errmsg, err);
        cb && cb(new Error(errmsg));
    }
}

module.exports.computeToken = computeToken;
function computeToken(id, secret, caOrg, channel, timeoutsec, cb) {
    if (!timeoutsec || timeoutsec < 0) {
        timeoutsec = parseInt(hfc.getConfigSetting('login_token_timeout_sec'));
    }
    var timestamp = Math.floor(new Date().getTime() / 1000) + timeoutsec;

    var token = [timestamp, id, secret, caOrg, channel];
    var tokenString = JSON.stringify(token);
    var tokenHex = kms.encryptAesSymKeyToken(serverKey, tokenString, serverIv);
    if (!tokenHex) {
        logger.debug( "failed to get token:", tokenString);
        cb && cb(new Error("Failed to get token"));
    }
    else {
        logger.debug("Successfully got token:", tokenHex);
        cb && cb(null, tokenHex);
    }
}

module.exports.loginByAuthCode = loginByAuthCode;
function loginByAuthCode(authCode, timeoutsec, cb) {
    logger.debug("trying to get login token by: " + authCode);
    appIDHelper.getUserWithAuthCode(authCode).then((user) => {
        if(user) {
            if (!timeoutsec || timeoutsec < 0) {
                timeoutsec = parseInt(hfc.getConfigSetting('login_token_timeout_sec'));
            }
            var timestamp = Math.floor(new Date().getTime() / 1000) + timeoutsec;
            var userAttributes = user.attributes;
            var attrList = userAttributes.data;
            var id = userAttributes.enrollId;
            var secret = userAttributes.enrollSecret;
            var caOrg = attrList.find(attr => attr.name === 'caOrg').value;
            var channel = attrList.find(attr => attr.name === 'channel').value;
            var pubkey = attrList.find(attr => attr.name === 'pubkey').value;
            var token = [timestamp, id, secret, caOrg, channel];
            var tokenString = JSON.stringify(token);
            var tokenHex = kms.encryptAesSymKeyToken(serverKey, tokenString, serverIv);
            if (!tokenHex) {
                var errmsg = 'Failed to get login token';
                logger.error(errmsg);
                cb && cb(new Error(errmsg));
            } else {
                let ret = {
                    id: id,
                    secret: secret,
                    token: tokenHex,
                    public_key: pubkey
                };
                logger.info("Successfully got user with auth code:", id);
                cb && cb(null, ret);
            }
        } else {
            var errmsg = 'Failed to get user with auth code';
            logger.error(errmsg);
            cb && cb(new Error(errmsg));
        }
    }).catch((err) => {
        var errmsg = "Failed to get user with auth code";
        logger.error(errmsg, err);
        cb && cb(new Error(errmsg));
    });
}


module.exports.validateLoginToken = validateLoginToken;
function validateLoginToken(token, cb) {
    try {
        if (!token) {
            cb && cb(new Error('empty token'));
        }
        else {
            var timestamp = Math.floor(new Date().getTime() / 1000);
            var decryptedToken = kms.decryptAesSymKeyToken(serverKey, token, serverIv);
            var tokenList = JSON.parse(decryptedToken);
            if (timestamp > tokenList[0]) {
                logger.debug( "token expired", timestamp, tokenList[0]);
                cb && cb(new Error("token expired"));
            }
            else {
                logger.info("token validated for", tokenList[1], tokenList[3], tokenList[4]);
                cb && cb(null, tokenList);
            }
        }
    }
    catch (err) {
        var errmsg = "invalid token";
        logger.error(errmsg, err);
        cb && cb(new Error(errmsg));
    }
}

module.exports.isValidLoginToken = isValidLoginToken;
function isValidLoginToken(token, userid) {
    logger.debug("isValidLoginToken", token, userid);
    try {
        if (!token) {
            return false;
        }
        else {
            var timestamp = Math.floor(new Date().getTime() / 1000);
            logger.debug("trying to validate LoginToken: " + token);
            var decryptedToken = kms.decryptAesSymKeyToken(serverKey, token, serverIv);
            var tokenList = JSON.parse(decryptedToken);
            logger.debug("got token list", tokenList);
            if (timestamp > tokenList[0]) {
                logger.debug( "token expired", timestamp, tokenList[0]);
                return false;
            }
            else {
                if (!userid || userid == tokenList[1]) {
                    logger.debug("token verified for ", userid);
                    return true;
                } else {
                    logger.debug("user id and token does not match");
                    return false;
                }
            }
        }
    }
    catch (err) {
        var errmsg = "invalid token";
        logger.debug(errmsg, err);
        return false;
    }
}


module.exports.validateUserByHeaders = validateUserByHeaders;
function validateUserByHeaders(headers, cb) {
    try {
        if (!headers) {
            cb && cb(new Error('empty header'));
        }
        else {
            ums.validateUserByHeaders(headers, cb);
        }
    }
    catch (err) {
        var errmsg = "error validating user by header";
        logger.debug(errmsg, err);
        cb && cb(new Error(errmsg));
    }
}
