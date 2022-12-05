/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

"use strict";

var TAG = "ums_app_id.js";
var helper = require('../utils/ums_app_id_helper.js');
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var hfc = require('fabric-client');
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;
var umsModule = "ums_app_id.js";
var umsReady = false;

const defaultEmail = "TODO";
const defaultAdmin = "TODO";
const defaultAdminPassword = "TODO";
const defaultUsername = "TODO";
const defaultRole = "system";
const defaultEnrollSecret = "TODO"; //EnrollSecret is mapped to application password

//============================================================
// UMS App ID interface functions
//============================================================

/**
 * setup registers default app admin user
 * if successful, umsReady will be set to true
 */
module.exports.setup = function () {
    var registrar = {
        id: defaultAdmin,
        password: defaultAdminPassword,
        name: defaultUsername,
        role: defaultRole,
        enrollId: defaultAdmin,
        enrollSecret: defaultEnrollSecret,
        email: defaultEmail,
        data: {}
    };

    try {
        logger.info("ums AppID configured");
        umsReady = true;
    } catch (err) {
        logger.debug("Failed to set up UMS App ID: " + err);
        throw new Error("Failed to set up UMS App ID: " + err);
    }
};

/**
 * getUmsModule returns the ums module being used
 */
module.exports.getUmsModule = getUmsModule;
function getUmsModule() {
    return umsModule;
}

/**
 * ready returns a Boolean flag indicating if ums is ready for use
 * @registrar {Object} not used
 */
module.exports.ready = ready;
function ready(registrar) {
    return umsReady;
}

/**
 * setupDefaultLoginUser is a helper function for setting up default admin user
 * @registrar {Object} login user to be registered in App ID
 */
module.exports.setupDefaultLoginUser = setupDefaultLoginUser;
function setupDefaultLoginUser(registrar) {
    return registerLoginUser(registrar.id, registrar.name, registrar.password, registrar.enrollId, registrar.enrollSecret, registrar.role, registrar.email, registrar.attr);
}

/**
 * registerLoginUser creates or updates an user to App ID
 * @id {String} application user ID
 * @password {String} App ID password
 * @email {String} App ID email
 * @enrollSecret {String} application's password
 * @ attr {any} used to store any other information
 */
module.exports.registerLoginUser = registerLoginUser;
function registerLoginUser(id, name, password, enrollId, enrollSecret, role, email, attr, cb) {
    var accessToken = "";

    var userData = {
        id: id,
        name: name,
        password: password,
        role: role,
        enrollId: enrollId,
        enrollSecret: enrollSecret,
        email: email,
        data: attr
    };

    // First get app auth token
    helper.getApplicationAuthToken().then((appIdAccessToken) => {
        accessToken = appIdAccessToken;
        // See if user exists by trying to login
        return helper.loginAppID(id, password)

    }).then((idToken) => {
        logger.info("user already exists");
        // user exists, decode ID token
        return helper.decodeLoginUserIDToken(idToken);

    }).then((user) => {
        // We also want to pass back UUID so caller can save it
        userData["uuid"] = user.sub;

        logger.info("proceed to save user attributes in AppID");
        return helper.setUserAttribute(accessToken, user.sub, id, name, password, enrollId, enrollSecret, role, email, attr);

    }).then((result) => {
        logger.info("Saved user attributes in AppID");
        return cb && cb(null, userData);

    }).catch((err) => {
        logger.info("user does not exist yet");
        // register user to cloud directory
        // right now we can just use name as both first name and last name
        helper.registerLoginUser(accessToken, id, password, email, name, name).then((setUpResult) => {
            //return helper.loginAppID(email, password);
            return helper.loginAppID(id, password);
        }).then((idToken) => {
            return helper.decodeLoginUserIDToken(idToken);

        }).then((user) => {
            // We also want to pass back UUID so caller can save it in
            userData["uuid"] = user.sub;

            logger.info("proceed to save user attributes in AppID");
            return helper.setUserAttribute(accessToken, user.sub, id, name, password, enrollId, enrollSecret, role, email, attr);

        }).then((result) => {
            logger.info("Saved user attributes in AppID");
            return cb && cb(null, userData);

        }).catch((err) => {
            var errmsg = "register login user failed: ";
            logger.error(errmsg, err);
            cb && cb(err);
        });
    });
}

/**
 * changePassword changes App ID login password
 * @id {String} AppID email
 * @password {String} old AppID password
 * @newPassword {String} new AppID password, it is a new field
 * @token {String} not used, pass empty String
 */
module.exports.changePassword = changePassword;
function changePassword(id, password, token, newPassword, cb) {
    var accessToken = "";
    var loginUser = {};

    // First get app auth token
    helper.getApplicationAuthToken().then((appIdAccessToken) => {
        accessToken = appIdAccessToken;
        // Login as the user to get idToken
        return helper.loginAppID(id, password)

    }).then((idToken) => {
        // decode ID token
        return helper.decodeLoginUserIDToken(idToken);

    }).then((user) => {
        logger.info("Got user. Proceed to change password");
        loginUser = user;
        if (user.identities) {
            if (user.identities[0].id) {
                return helper.changePassword(accessToken, user.identities[0].id, newPassword)
            } else {
                throw new Error('Missing user identities ID');
            }
        } else {
            throw new Error('Missing user identities');
        }

    }).then((result) => {
        logger.info("Changed password complete, proceed to update user profile in AppID with new password");
        return helper.setUserAttribute(accessToken, loginUser.sub, loginUser.id, loginUser.name, newPassword, loginUser.enrollId, loginUser.enrollSecret, loginUser.role, loginUser.email, loginUser.attr)

    }).then((result) => {
        logger.info("Changed password complete, try login with new password");
        return helper.loginAppID(id, newPassword)

    }).then((idToken) => {
        logger.info("All set");
        cb && cb(null, "Change password complete");

    }).catch((err) => {
        var errmsg = "Change password failed ";
        logger.error(errmsg, err);
        cb && cb(err);
    });
}

/**
 * changePassword changes App ID login password
 * @id {String} user id
 */
module.exports.forgetPassword = forgetPassword;
function forgetPassword(id, cb) {
    helper.getApplicationAuthToken().then((appIdAccessToken) => {
        return helper.forgetPassword(appIdAccessToken, id)
    }).then((result) => {
        logger.info("Reset password complete");
        cb && cb(null, result);
    }).catch((err) => {
        var errmsg = "Reset password failed ";
        logger.error(errmsg, err);
        cb && cb(err);
    });
}

/**
 * getLoginUser returns the user object stored in App ID
 * @id {String} AppID email
 * @password {String} AppID password, it is a new field
 */
module.exports.getLoginUser = getLoginUser;
function getLoginUser(id, password, cb) {
    var accessToken = "";

    // First get app auth token
    helper.getApplicationAuthToken().then((appIdAccessToken) => {
        accessToken = appIdAccessToken;
        // Login as the user to get idToken
        return helper.loginAppID(id, password)

    }).then((idToken) => {
        // decode ID token
        return helper.decodeLoginUserIDToken(idToken);

    }).then((user) => {
        return helper.getLoginUser(accessToken, user.sub);

    }).then((loginUser) => {
        logger.info("Got login user:" + id);
        cb && cb(null, loginUser);

    }).catch((err) => {
        var errmsg = "Get login user failed: ";
        logger.error(errmsg, err);
        cb && cb(err);
    });
}

/**
 * validateLoginUser validates email and password against AppID user profile
 * @id {String} AppID email
 * @password {String} AppID password
 * @data {String} not used, pass empty String
 */
module.exports.validateLoginUser = validateLoginUser;
function validateLoginUser(id, password, data, cb) {
    // Add org and channel
    var caOrg = data && data["org"] ? data["org"] : null;
    var channel = data && data["channel"] ? data["channel"] : null;
    var accessToken = "";

    // First get app auth token
    helper.getApplicationAuthToken().then((appIdAccessToken) => {
        accessToken = appIdAccessToken;
        // Login as the user to get idToken
        return helper.loginAppID(id, password)

    }).then((idToken) => {
        // decode ID token
        return helper.decodeLoginUserIDToken(idToken);

    }).then((user) => {
        return helper.getLoginUser(accessToken, user.sub);

    }).then((loginUser) => {
        let user = loginUser.attributes;
        user.caOrg = caOrg;
        user.channel = channel;
        // user.enrollSecret is mapped to application password
        if (user && user.password === password && user.id === id) {
            logger.info("Got login user successfully from App ID:", id);
            cb && cb(null, user);
        } else {
            cb && cb(new Error("Password or ID does not match"));
        }

    }).catch((err) => {
        var errmsg = "Validate login user failed: ";
        logger.error(errmsg, err);
        cb && cb(err);
    });
}

/**
 * validateUserByHeaders validates login user with headers
 * @headers {request header} request header; App ID email and password must be stored in headers
 */
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
            var id = headers["email"];
            var password = headers["password"];
            if (!id || !password) {
                cb && cb(new Error("Invalid headers, missing ID or password"));
            } else {
                validateLoginUser(id, password, {}, function (err, user) {
                    ;
                    if (err) {
                        var errmsg = "Error validating by header";
                        logger.error(errmsg, err);
                        cb && cb(new Error(errmsg));
                    } else if (!user) {
                        logger.error("Errror validating by header, user is empty");
                        cb && cb(new Error("Error validating by header, user is empty"));
                    } else {
                        var timestamp = Math.floor(new Date().getTime() / 1000);
                        // token is composed of timestamp, AppID email and AppID password
                        var token = [timestamp, user.email, user.password];
                        logger.info("Validating headers returning token for", user.email);
                        cb && cb(null, token);
                    }
                });
            }
        }
    } catch (err) {
        var errmsg = "Error validating by header";
        logger.error(errmsg, err);
        cb && cb(new Error(errmsg));
    }
}

/**
 * loginUserByHeaders logs in user to App ID with headers
 * @req {request} request; App ID email and password must be stored in headers
 * @res {response} response
 * @next {function} next function to be executed when this is done
 * @cb {function} callback, not used
 */
module.exports.loginUserByHeaders = loginUserByHeaders;
function loginUserByHeaders(req, res, next, cb) {
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
            var id = req.headers["email"];
            var password = req.headers["password"];
            if (!id || !password) {
                logger.error("Invalid headers");
                res.redirect(getLogoutUrl());
            } else if (id === req.session.email) {
                logger.info("Already logged in");
                next();
            } else {
                // login to AppID
                // First get app auth token
                helper.getApplicationAuthToken().then((appIdAccessToken) => {
                    accessToken = appIdAccessToken;
                    // Login as the user to get idToken
                    return helper.loginAppID(id, password)

                }).then((idToken) => {
                    // decode ID token
                    return helper.decodeLoginUserIDToken(idToken);

                }).then((user) => {
                    return helper.getLoginUser(accessToken, user.sub);

                }).then((loginUser) => {
                    logger.info("Got login user");
                    let user = loginUser.attributes;

                    // application password is stored in enrollSecret field of AppID
                    req.body.password = loginUser.enrollSecret;
                    req.body.id = loginUser.id;
                    request_handler.login(req, res, next, getLogoutUrl(), 10 * 3600);

                }).catch((err) => {
                    var errmsg = "Error logging in by header";
                    logger.error(errmsg, err);
                    res.redirect(getLogoutUrl());
                });
            }
        }
    } catch (err) {
        var errmsg = "Error logging in by header";
        logger.error(errmsg, err);
        res.redirect(getLogoutUrl());
    }
}

/**
 * getDefaultPassword gets default admin user's password
 * @cb {function} callback, not used
 */
module.exports.getDefaultPassword = getDefaultPassword;
function getDefaultPassword(cb) {
    return defaultAdminPassword;
}

/**
 * getLoginUrl gets login url
 * @cb {function} callback, not used
 */
module.exports.getLoginUrl = getLoginUrl;
function getLoginUrl(cb) {
    return "/loginLocal";
}

/**
 * getLogoutUrl gets logout url
 * @cb {function} callback, not used
 */
module.exports.getLogoutUrl = getLogoutUrl;
function getLogoutUrl(cb) {
    return "/logoutLocal";
}

/**
 * getChangePasswordUrl gets changePassword url
 * @cb {function} callback, not used
 */
module.exports.getChangePasswordUrl = getChangePasswordUrl;
function getChangePasswordUrl(cb) {
    return "/changePasswordLocal";
}