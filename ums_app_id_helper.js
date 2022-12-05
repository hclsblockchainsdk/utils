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
var jwt_decode = require('jwt-decode');
var path = require('path');
var TAG = "ums_app_id_helper.js";
var log4js = require('log4js');
var hfc = require('fabric-client');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;
var fs = require('fs');

// TODO: this need to be implemented better
const appIDConfigFile = hfc.getConfigSetting('app_id_config_file') ? fs.readFileSync(path.resolve(path.join(__dirname, '../..', hfc.getConfigSetting('app_id_config_file')))) : null;
const appIDConfig = appIDConfigFile ? JSON.parse(appIDConfigFile) : {};
const apiKey = appIDConfig.apikey;
const appClientID = appIDConfig.clientId;
const appSecret = appIDConfig.secret;
const managementUrl = appIDConfig.managementUrl;
const oauthServerUrl = appIDConfig.oauthServerUrl;
const appIDTokenUrl = hfc.getConfigSetting('appid_token_url') ? hfc.getConfigSetting('appid_token_url') : "https://iam.cloud.ibm.com/identity/token";
const defaultEmail = hfc.getConfigSetting('appid_token_url');
const defaultAdmin = hfc.getConfigSetting('appid_admin') ? hfc.getConfigSetting('appid_admimn') : "AppAdmin";
const defaultAdminPassword = hfc.getConfigSetting('appid_admin_password') ? hfc.getConfigSetting('appid_admimn_password') : "pass0pass0";
const httpsEnabled = hfc.getConfigSetting('enable_https');
const redirectURL = hfc.getConfigSetting('redirect_uri');

module.exports.getApplicationAuthToken = getApplicationAuthToken;
function getApplicationAuthToken() {
    return new Promise((resolve, reject) => {
        const formData = {
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": apiKey
        }

        var errmsg = "err getting auth token with application's API key";
        request.post({ url: appIDTokenUrl, form: formData }, function (err, res, result) {
            if (err) {
                logger.error(errmsg, err);
                reject(errmsg);
            }
            else if (res.statusCode !== 200) {
                // logger.debug(res.statusCode);
                logger.error(errmsg);
                reject(errmsg);
            }
            else {
                logger.debug("result " + result);
                resolve(JSON.parse(result).access_token);
            }
        });
    });
}

module.exports.registerLoginUserWithSignUp = registerLoginUserWithSignUp;
function registerLoginUserWithSignUp(appIdAccessToken, username, password, email, firstName, lastName) {
    return new Promise((resolve, reject) => {
        let apiUrl = managementUrl + "/cloud_directory/sign_up";

        let loginUser = {
            "displayName": firstName + " " + lastName,
            "active": true,
            "emails": [
                {
                    "value": email,
                    "primary": true
                }
            ],
            "userName": username,
            "password": password
        };

        let options = {
            uri: apiUrl,
            method: 'POST',
            auth: {
                'bearer': appIdAccessToken
            },
            headers: {
                'Content-Type': 'application/json'
            },
            json: true,
            body: loginUser
        };

        var errmsg = "create login user error";
        request(options, function (err, res, result) {
            if (err) {
                logger.error(errmsg, err);
                reject(errmsg);
            }
            else if (res.statusCode != 201) {
                logger.error(errmsg);
                reject(errmsg);
            }
            else {
                // return registration result
                resolve(result);
            }
        });
    });
}

module.exports.registerLoginUser = registerLoginUser;
function registerLoginUser(appIdAccessToken, username, password, email, firstName, lastName) {
    return new Promise((resolve, reject) => {
        let apiUrl = managementUrl + "/cloud_directory/Users";

        let loginUser = {
            "displayName": firstName + " " + lastName,
            "userName": username,
            "password": password,
            "emails": [
                {
                    "value": email,
                    "primary": true
                }
            ],
            "name": {
                "givenName": firstName,
                "familyName": lastName,
                "formatted": firstName + " " + lastName
            },
            "status": "CONFIRMED"
        };

        let options = {
            uri: apiUrl,
            method: 'POST',
            auth: {
                'bearer': appIdAccessToken
            },
            headers: {
                'Content-Type': 'application/json'
            },
            json: true,
            body: loginUser
        };

        logger.info(options);
        var errmsg = "create login user error";
        request(options, function (err, res, result) {
            if (err) {
                logger.debug(err);
                logger.error(errmsg, err);
                reject(errmsg);
            }
            else if (res.statusCode !== 201) {
                logger.debug(res);
                logger.error(errmsg);
                reject(errmsg);
            }
            else {
                logger.debug(result);
                // return registration result
                resolve(result);
            }
        });
    });
}

module.exports.loginAppID = loginAppID;
function loginAppID(email, password) {
    return new Promise((resolve, reject) => {
        let formData = {
            "grant_type": "password",
            "username": email,
            "password": password
        };

        let apiUrl = oauthServerUrl + "/token";

        let options = {
            uri: apiUrl,
            method: 'POST',
            auth: {
                user: appClientID,
                pass: appSecret,
            },
            form: formData
        };

        var errmsg = "failed to login as " + email;
        request(options, function (err, res, result) {
            if (err) {
                logger.debug(errmsg, err);
                reject(errmsg);
            }
            else if (res.statusCode !== 200) {
                logger.debug(errmsg);
                reject(errmsg);
            }
            else {
                logger.debug("loginAppID result: " + result);
                // return registration result
                resolve(JSON.parse(result).id_token);
                //resolve(JSON.parse(result));
            }
        });
    });
}

module.exports.changePassword = changePassword;
function changePassword(appIdAccessToken, uuid, newPassword) {
    return new Promise((resolve, reject) => {
        let formData = {
            "uuid": uuid,
            "newPassword": newPassword
        };

        let options = {
            uri: managementUrl + "/cloud_directory/change_password",
            auth: {
                'bearer': appIdAccessToken
            },
            form: formData,
        };

        let errmsg = "err changing password in App ID";
        request.post(options, function (err, res, result) {
            if (err) {
                logger.error(errmsg, err);
                reject(errmsg);
            }
            else if (res.statusCode != 200) {
                logger.debug(res.statusCode);
                logger.error(errmsg);
                reject(errmsg);
            }
            else {
                // return access token
                resolve(result);
            }
        });
    });
}

module.exports.forgetPassword = forgetPassword
function forgetPassword(appIdAccessToken, userId) {
    return new Promise((resolve, reject) => {
        let formData = {
            "user": userId
        }
        let options = {
            uri: managementUrl + '/cloud_directory/forgot_password?language=en',
            auth: {
                'bearer': appIdAccessToken
            },
            form: formData,
        };
        let errmsg = "Failed to send reset password email";
        request.post(options, function (err, res, result) {
            if (err) {
                logger.error(errmsg, err);
                reject(err);
            }
            else if (res.statusCode != 200) {
                logger.debug(res.statusCode);
                logger.error(errmsg);
                reject(res);
            }
            else {
                resolve(result);
            }
        });
    });
}

// Used for password mapping
// Can only be set after login
module.exports.setUserAttribute = setUserAttribute;
function setUserAttribute(appIdAccessToken, UUID, id, name, password, enrollId, enrollSecret, role, email, attr) {
    return new Promise((resolve, reject) => {
        let apiUrl = managementUrl + "/users/" + UUID + "/profile";

        let requestBody = {
            "attributes": {
                "id": id,
                "password": password,
                "role": role,
                "enrollId": enrollId,
                "enrollSecret": enrollSecret,
                "email": email,
                "data": attr
            }
        }

        let options = {
            uri: apiUrl,
            method: 'PUT',
            auth: {
                'bearer': appIdAccessToken
            },
            headers: {
                'Content-Type': 'application/json'
            },
            json: true,
            body: requestBody
        };

        var errmsg = "set user attribute error";
        request(options, function (err, res, result) {
            if (err) {
                logger.error(errmsg, err);
                reject(errmsg);
            }
            else if (res.statusCode != 200) {
                logger.debug(res.statusCode);
                logger.error(errmsg);
                reject(errmsg);
            }
            else {
                // return set attribute result
                resolve(result);
            }
        });
    });
}

module.exports.getLoginUser = getLoginUser;
function getLoginUser(appIdAccessToken, UUID) {
    logger.debug("appIdAccessToken:" + appIdAccessToken);
    logger.debug("UUID:" + UUID);
    return new Promise((resolve, reject) => {
        let apiUrl = managementUrl + "/users/" + UUID + "/profile";

        let options = {
            uri: apiUrl,
            method: 'GET',
            auth: {
                'bearer': appIdAccessToken
            },
            headers: {
                'Content-Type': 'application/json'
            },
            json: true
        };

        var errmsg = "get login user (AppID) error";
        request(options, function (err, res, result) {
            if (err) {
                logger.error(errmsg, err);
                reject(errmsg);
            }
            else if (res.statusCode != 200) {
                logger.debug(res.statusCode);
                logger.error(errmsg);
                reject(errmsg);
            }
            else {
                // return set attribute result
                resolve(result);
            }
        });
    });
}

module.exports.decodeLoginUserIDToken = decodeLoginUserIDToken;
function decodeLoginUserIDToken(token) {
    return jwt_decode(token);
}

module.exports.getUserWithAuthCode = getUserWithAuthCode;
function getUserWithAuthCode(code) {
    return new Promise((resolve, reject) => {
        let formData = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirectURL
        };

        let apiUrl = oauthServerUrl + "/token";

        let options = {
            uri: apiUrl,
            method: 'POST',
            auth: {
                user: appClientID,
                pass: appSecret,
            },
            form: formData
        };

        var errmsg = "failed to get user with auth code: " + code;
        request(options, function (err, res, result) {
            if (err) {
                logger.debug(errmsg, err);
                reject(errmsg);
            }
            else if (res.statusCode !== 200) {
                logger.debug(errmsg);
                reject(errmsg);
            }
            else {
                getApplicationAuthToken().then((appIdAccessToken) => {
                    logger.debug("\nGot application access token: ")
                    logger.debug(appIdAccessToken);

                    // return registration result
                    const userID = decodeLoginUserIDToken(JSON.parse(result).id_token).sub;
                    getLoginUser(appIdAccessToken, userID).then((user) => {
                        logger.debug("Got user with auth code: " + user);
                        resolve(user);
                    }).catch(err => reject(err));
                });
            }
        });
    });
}

module.exports.testAppIDSetUp = testAppIDSetUp;
function testAppIDSetUp(requireSignUp) {
    logger.debug("testAppIDSetUp");

    var accessToken = "";
    var user = {};

    getApplicationAuthToken().then((appIdAccessToken) => {
        accessToken = appIdAccessToken;
        logger.debug("\nGot application access token: ")
        logger.debug(appIdAccessToken);
        if (requireSignUp) {
            return registerLoginUserWithSignUp(appIdAccessToken, defaultAdmin, defaultAdminPassword, defaultEmail, "App", "Admin");
        } else {
            return registerLoginUser(appIdAccessToken, defaultAdmin, defaultAdminPassword, defaultEmail, "App", "Admin")
        }
    }).then((setUpResult) => {
        logger.debug("----------------------------------------------------------------");
        logger.info("AppAdmin set up properly");
        return setUpResult.id;

    }).then((id) => {
        logger.debug("----------------------------------------------------------------");
        logger.debug("Log in as App Admin");
        return loginAppID(defaultEmail, defaultAdminPassword);

    }).then((token) => {
        logger.debug("----------------------------------------------------------------");
        logger.debug("Got ID token: ")
        logger.debug(token);
        user = decodeLoginUserIDToken(token);
        return decodeLoginUserIDToken(token);

    }).then((done) => {
        logger.debug("----------------------------------------------------------------");
        logger.debug("Got decoded user appID UUID:");
        logger.debug(user.sub);
        return setUserAttribute(accessToken, user.sub, defaultAdmin, "App Admin", defaultAdminPassword, defaultAdmin, "pass0", "system", defaultEmail, {});

    }).then((setAttributeResult) => {
        logger.debug("----------------------------------------------------------------");
        logger.debug("Got decoded user Cloud Directory UUID:");
        logger.debug(user.identities[0].id);
        return changePassword(accessToken, user.identities[0].id, "pass1pass1")

    }).then((result) => {
        logger.debug("----------------------------------------------------------------");
        logger.debug("Changed password complete");
        return loginAppID(defaultEmail, "pass1pass1");

    }).then((token) => {
        logger.debug("----------------------------------------------------------------");
        logger.debug("Got id_token with new password " + token);

        logger.debug("----------------------------------------------------------------");
        logger.debug("Get AppID user profile");
        return getLoginUser(accessToken, user.sub)

    }).then((userProfile) => {
        logger.debug("Got application password from login user profile: ");
        logger.debug(userProfile.attributes.password);

        logger.debug("----------------------------------------------------------------");
        logger.debug("All set");

    }).catch((err) => {
        var errmsg = "AppAdmin set up failed: ";
        logger.error(errmsg, err);
        return err;
    });
}