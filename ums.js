/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

"use strict";
var ums = {}

// Use a tag to make logs easier to find
var TAG = "ums.js";
var hfc = require('fabric-client');
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

var umsmodule = "";

module.exports.setup = function () {
    umsmodule = hfc.getConfigSetting('ums_module') || "ums_blockchian.js";
    if (!umsmodule || umsmodule == "") {
        //umsmodule = "ums_local.js";
        umsmodule = "ums_blockchain.js";
        //umsmodule = "ums_pdt.js";

    }
    logger.info("ums_moduleE=", umsmodule);
    ums = require("../utils/" + umsmodule);
    ums.setup();

    logger.info("ums configured");
};


//============================================================
// UMS interface functions
//============================================================
module.exports.getUmsModule = getUmsModule;
function getUmsModule() {
    return umsmodule;
}

//ready
module.exports.ready = ready;
function ready(registrar) {
    return ums.ready();
}

//set default user
module.exports.setupDefaultLoginUser = setupDefaultLoginUser;
function setupDefaultLoginUser(registrar) {
    return ums.setupDefaultLoginUser(registrar);
}

//update or create login user
//return error if failed, or null if succeed
module.exports.registerLoginUser = registerLoginUser;
function registerLoginUser(id, name, password, enrollId, enrollSecret, role, email, attr, cb) {
    return ums.registerLoginUser(id, name, password, enrollId, enrollSecret, role, email, attr, function (err, loginUser, msg) {
        cb && cb(err, loginUser, msg);
    });
}

// return the message
module.exports.changePassword = changePassword;
function changePassword(id, password, token, cb) {
    return ums.changePassword(id, password, token, function (err, msg) {
        cb && cb(err, msg);
    });
}

// return the login User object
module.exports.getLoginUser = getLoginUser;
function getLoginUser(id, cb) {
    return ums.getLoginUser(id, function (err, user) {
        cb && cb(err, user);
    });
}

// validate userId and password
module.exports.validateLoginUser = validateLoginUser;
function validateLoginUser(id, password, data, cb) {
    return ums.validateLoginUser(id, password, data, function (err, userData) {
        cb && cb(err, userData);
    });
}

// reset password
module.exports.forgetPassword = forgetPassword;
function forgetPassword(id, cb) {
    return ums.forgetPassword(id, function (err, res) {
        cb && cb(err, res);
    });
}

// validate user with Headers
module.exports.validateUserByHeaders = validateUserByHeaders;
function validateUserByHeaders(headers, cb) {
    return ums.validateUserByHeaders(headers, function (err, token) {
        cb && cb(err, token);
    });
}

// login user with headers
// cb not used
module.exports.loginUserByHeaders = loginUserByHeaders;
function loginUserByHeaders(req, res, next, cb) {
    return ums.loginUserByHeaders(req, res, next, cb);
}

//get default password
//cb not used
module.exports.getDefaultPassword = getDefaultPassword;
function getDefaultPassword(cb) {
    return ums.getDefaultPassword(cb);
}

// get login url
// cb not used
module.exports.getLoginUrl = getLoginUrl;
function getLoginUrl(cb) {
    return ums.getLoginUrl(cb);
}

//get logout url
// cb not used
module.exports.getLogoutUrl = getLogoutUrl;
function getLogoutUrl(cb) {
    return ums.getLogoutUrl(cb);
}

//get changePassword url
// cb not used
module.exports.getChangePasswordUrl = getChangePasswordUrl;
function getChangePasswordUrl(cb) {
    return ums.getChangePasswordUrl(cb);
}

