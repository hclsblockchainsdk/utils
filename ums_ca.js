/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

"use strict";
var chain_helper = require('../utils/chain_helper.js');

var hfc = require('fabric-client');

// Use a tag to make logs easier to find
var TAG = "ums_ca.js";
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

var adminUser = null;

module.exports.setup = function () {    
    //setupDefaultLoginUser(adminUser);
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
    cb && cb(new Error("not implemented"));
}


//return the message
module.exports.changePassword = changePassword;
function changePassword(id, password, token, cb) {
    cb && cb(new Error("not implemented"));
}


// return the login User object
module.exports.getLoginUser = getLoginUser;
function getLoginUser(id, cb) {
    cb && cb(new Error("not implemented"));
}

// validate userId and password
module.exports.validateLoginUser = validateLoginUser;
function validateLoginUser(id, password, data, cb) {
    var org = data && data["org"] ? data["org"] : null;
    var channel = data && data["channel"] ? data["channel"] : null;
    var isOrginChannel = chain_helper.isOrgInChannel(channel, org);
    if (!isOrginChannel) {
        cb && cb(new Error('invalid channel or org is not in channel'));
    } else {
            let attr_reqs = [{name: "role"}];
        chain_helper.enrollUser(id, password, org, attr_reqs).then((enrollment) => {
            let role = null;
            let amap = chain_helper.getAttributesFromEnrollCert(enrollment.certificate, false);
            if (amap["attrs"] && amap["attrs"]["role"]) {
                role = amap["attrs"]["role"];
            }
            var userdata = {
                id: id,
                name: id,
                password: password,
                email: null,
                role: role,
                enrollId: id,
                enrollSecret: password,
                caOrg: org,
                channel: channel,
                attr: null
            };
            cb && cb(null, userdata);
        },(err) => {
            cb && cb(new Error('enroll failed'));
        } );
    }
}

//validate user with Headers
module.exports.validateUserByHeaders = validateUserByHeaders;
function validateUserByHeaders(headers, cb) {
    cb && cb(new Error("Authentication by header not allowed with CA"));
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
