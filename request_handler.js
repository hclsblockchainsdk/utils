/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

//For debugging
var TAG = 'request_handler.js';
var hfc = require('fabric-client');
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

//Load our modules.
var user_manager = require('../utils/user_manager.js');
var chain_helper = require('../utils/chain_helper');

//Make sure that the following is pointing to chaincode_ops for your solutions
var chaincodeOps = require('../utils/chaincode_ops.js');

var solutionConfig = {};
module.exports.setup = function (config) {
    solutionConfig = config;
    this.solutionConfig = config;
    chaincodeOps.setup(solutionConfig);
};

const invalidDataError = 400;
const unauthorizedError = 401;
const serverError = 500;

module.exports.clearMessage = clearMessage;
function clearMessage(req, res) {
    var msg = req.query.msg;

    if (!msg || msg === "") {
        msg = "all";
    }

    if (msg === "error_msg") {
        req.session.error_msg = null;
    } else if (msg === "success_msg") {
        req.session.success_msg = null;
    } else if (msg === "login_error_msg") {
        req.session.login_error_msg = null;
    } else if (msg === "reg_error_msg") {
        req.session.reg_error_msg = null;
    } else if (msg === "all") {
        req.session.error_msg = null;
        req.session.success_msg = null;
        req.session.login_error_msg = null;
        req.session.reg_error_msg = null;
    } else if (msg === "all_err") {
        req.session.error_msg = null;
        req.session.login_error_msg = null;
        req.session.reg_error_msg = null;
    }

    res.json({ message: "clearMessage Done: " + msg });
}

function convertErrorFromJson(err) {
    try {
        let jsonError = JSON.parse(err.message);
        return { msg: jsonError.message, status: jsonError.status };
    } catch (err2) {
        //JSON.parseFails we ignore and send regular error
    }
    let statusCode = err.message.startsWith('Invalid') ? invalidDataError : serverError;
    return { msg: err.message, status: statusCode }
}


//============================================================
//API
//============================================================
function getLoginTokenApiHandler(caller, data, req, res) {
    logger.debug('getLoginToken');
    let user_data = {
        org: data.org,
        channel: data.channel,
    };

    let pubkey = solutionConfig["app_admin"]["public_key"];
    if (!pubkey.startsWith("-----BEGIN")) {
        pubkey = "-----BEGIN PUBLIC KEY-----\n" + pubkey + "\n-----END PUBLIC KEY-----\n";
    }
    user_manager.getLoginToken(data.id, data.password, user_data, function (err, token, user) {
        if (err) {
            let ret = {
                msg: "unable to get token",
                error: err
            };
            res.set('WWW-Authenticate', 'Basic realm="bundled_payments"');
            res.json(ret);
            res.status(unauthorizedError);
        } else {
            let ret = {
                id: user.enrollId,
                name: user.name,
                secret: user.enrollSecret,
                token: token,
                public_key: pubkey
            };
            req.session["token"] = token;
            res.json(ret);
        }
    }, data.timeout);
}

function getRefreshTokenApiHandler(caller, data, req, res) {
    logger.debug('get refresh token');
    user_manager.computeToken(caller.id, caller.secret, caller.org, caller.channel, data.timeout, function(err, token){
        if(err !== null) {
            res.status(500).json({ msg: "Failed to get refresh token.", status: 500 });
        } else {
            logger.debug("token in getRefreshTokenApiHandler: " + token);
            res.status(200).json({ token: token});
        }
    });
}

function updateOrgApiHandler(caller, data, req, res) {
    logger.debug('update org');

    chaincodeOps.getOrg(caller, data.id, function (err, user) {
        if (err != null || !user) {
            var errmsg = "Org not found";
            logger.error(errmsg, err);
            res.status(404).json({ msg: errmsg, status: 404 });
        } else if (!user.secret) {
            var errmsg = "Unauthorized to update the org";
            logger.error(errmsg, err);
            res.status(401).json({ msg: errmsg, status: 401 });
        } else if (data.secret && user.secret && user.secret != data.secret) {
            var errmsg = "Org admin's secret cannot be changed";
            logger.error(errmsg, err);
            res.status(400).json({ msg: errmsg, status: 400 });
        } else {
            logger.debug("Existing Org found: ", data.id);
            data.secret = user.secret;
            registerOrg(caller, data, req, res);
        }
    });
}

function registerOrg(caller, data, req, res) {
    logger.debug('registerOrg');

    var failIfExist = caller.id ? false : true;
    try {
        // 1. register user in CA
        user_manager.registerUser(data.id, data.secret, data.role, data.ca_org, data.email, data.verify_key, data.private_key, data.public_key, data.sym_key, failIfExist).then(attrList => {
            // 2. register user in chaincode
            var is_group = data.is_group == "true" || data.is_group == true
            var solution_private_data = data.data;
            solution_private_data.tax_id = data.tax_id;
            solution_private_data.address = data.address;
            var solution_public_data = {
                solution_level_role: data.solution_level_role,
            }

            var userInfo = {
                id: data.id,
                name: data.name,
                role: data.role,
                is_group: is_group,
                status: data.status,
                email: data.email,
                secret: data.secret,
                solution_public_data: solution_public_data,
                solution_private_data: solution_private_data
            };

            //keys
            for (let i = 0; i < attrList.length; i++) {
                let attr = attrList[i];
                if (attr["name"] == "prvkey") {
                    userInfo["private_key"] = attr["value"];
                } else if (attr["name"] == "pubkey") {
                    userInfo["public_key"] = attr["value"];
                } else if (attr["name"] == "symkey") {
                    userInfo["sym_key"] = attr["value"];
                }
            }

            chaincodeOps.registerOrg(caller, userInfo, function (err, result) {
                if (err != null) {
                    var errmsg = "Org is registered to CA, but failed to update org (CC):" + err.message;
                    logger.error(errmsg);
                    res.status(500).json({ msg: errmsg, status: 500 });
                } else {
                    logger.info('org registration completed successfully');
                    res.json({
                        id: data.id,
                        secret: data.secret,
                        msg: "org registration completed successfully",
                        tx_id: result.tx_id
                    });
                }
            });


        }).catch((err) => {
            var errmsg = "Failed to register org (CA):" + err.message;
            logger.error(errmsg, err);
            res.status(500).json({ msg: errmsg, status: 500 });
        });

    } catch (err) {
        var errmsg = "Failed to register org";
        logger.error(errmsg, err);
        res.status(500).json({ msg: errmsg, status: 500 });
    }

}


function registerOrgApiHandler(caller, data, req, res) {
    logger.debug('register org');

    chaincodeOps.getOrg(caller, data.id, function (err, user) {
        if (err == null && user) {
            var errmsg = "Existing org with same id found";
            logger.error(errmsg, err);
            res.status(400).json({ msg: errmsg, status: 400 });
        } else {
            logger.debug("Existing org not found: ", data.id);
            registerOrg(caller, data, req, res);
        }
    });
}

function registerUser(caller, data, req, res) {
    logger.debug('registerUser');

    //check user permission here
    //system can register system, auditor, org, patient
    //org can register service, patient
    //service can register patient
    //patient can self register

    var failIfExist = !caller.id;
    try {
        // 1. register user (CA) & enroll
        user_manager.registerUser(data.id, data.secret, data.role, data.ca_org, data.email, data.verify_key, data.private_key, data.public_key, data.sym_key, failIfExist).then(attrList => {
            // 2. register user in chaincode
            var is_group = data.is_group === "true" || data.is_group === true;
            var solution_private_data = data.data;
            var solution_public_data = {
                solution_level_role: data.solution_level_role,
            };
            var userInfo = {
                id: data.id,
                name: data.name,
                role: data.role,
                is_group: is_group,
                status: data.status,
                email: data.email,
                secret: data.secret,
                solution_public_data: solution_public_data,
                solution_private_data: solution_private_data
            };

            //keys
            for (let i = 0; i < attrList.length; i++) {
                let attr = attrList[i];
                if (attr["name"] === "prvkey") {
                    userInfo["private_key"] = attr["value"];
                } else if (attr["name"] === "pubkey") {
                    userInfo["public_key"] = attr["value"];
                } else if (attr["name"] === "symkey") {
                    userInfo["sym_key"] = attr["value"];
                }
            }


            chaincodeOps.registerUser(caller, userInfo, function (err, result) {
                if (err != null) {
                    var errmsg = "User is registered to CA, but failed to update user (CC):" + err.message;
                    logger.error(errmsg);
                    res.status(serverError).json({ msg: errmsg, status: serverError });
                } else {
                    logger.info('user registration completed successfully');
                    res.status(201).json({
                        id: data.id,
                        secret: data.secret,
                        msg: 'user registration completed successfully',
                        tx_id: result.tx_id
                    });
                }
            });


        }).catch((err) => {
            var errmsg = "Failed to register user (CA):" + err.message;
            logger.error(errmsg, err);
            res.status(serverError).json({ msg: errmsg, status: serverError });
        });

    } catch (err) {
        var errmsg = "Failed to register user";
        logger.error(errmsg, err);
        res.status(serverError).json({ msg: errmsg, status: serverError });
    }
}

function getOrgsApiHandler(caller, data, req, res) {
    logger.debug('getOrgs');
    chaincodeOps.getOrgs(caller, function (err, orgs) {
        if (err != null) {
            logger.error(err);
            res.json([]);
        } else {
            res.json(orgs);
        }
    });
}

function getOrgApiHandler(caller, data, req, res) {
    logger.debug('getOrg');
    chaincodeOps.getOrg(caller, data.id, function (err, org) {
        if (err != null) {
            logger.error(err);
            res.json({});
        } else {
            res.json(org);
        }
    });
}

function getUserApiHandler(caller, data, req, res) {
    logger.debug('getUser');
    chaincodeOps.getUser(caller, data.userid, function (err, user) {
        if (err != null) {
            logger.error(err);
            res.json({});
        } else {
            res.json(user);
        }
    });
}

function registerUserApiHandler(caller, data, req, res) {
    logger.debug('register user');

    chaincodeOps.getUser(caller, caller.id, function (err, callerData) {
        if (err == null && callerData) {
            chaincodeOps.getUser(caller, data.id, function (err, user) {
                if (err == null && user) {
                    var errmsg = "User " + data.id + " already exists";
                    logger.error(errmsg, err);
                    res.status(invalidDataError).json({ msg: errmsg, status: invalidDataError });
                } else {
                    logger.debug("Existing User not found: ", data.id);
                    caller.role = callerData.role;
                    registerUser(caller, data, req, res);
                }
            });
        } else {
            var errmsg = "Caller " + caller.id + " not found";
            logger.error(errmsg, err);
            res.status(invalidDataError).json({ msg: errmsg, status: invalidDataError});
        }
    });
}

function updateLoginUserApiHandler(enrollId, enrollSecret, data, req, res) {
    logger.debug('update login user');

    chaincodeOps.getUser(enrollId, data.id, function (err, user) {
        if (err != null) {
            var errmsg = "User not found";
            logger.error(errmsg, err);
            res.status(404).json({ msg: errmsg, status: 404 });
        } else {
            var userData = {
                id: data.id,
                name: data.name,
                password: data.password,
                email: data.email,
                data: data.data
            };

            chaincodeOps.updateLoginUser(enrollId, userData, function (err, result) {
                if (err != null) {
                    var errmsg = "Failed to update login user";
                    logger.error(errmsg, err);
                    res.status(500).json({ msg: errmsg, status: 500 });
                } else {
                    logger.info('login user updated successfully:', result);
                    res.json({
                        msg: result
                    });
                }
            });
        }
    });
}

function putUserInOrgApiHandler(caller, data, req, res) {
    logger.debug('put user in group');

    chaincodeOps.putUserInOrg(caller, data.userID, data.orgID, data.isAdmin, function (err, result) {
        if (err != null) {
            var errmsg = "Failed to put user in group";
            logger.error(errmsg, err);
            let statusAndMsg = convertErrorFromJson(err);
            res.status(statusAndMsg.status).json({ 'msg': statusAndMsg.msg });
        } else {
            logger.info('put user in group successfully');
            //this tx doesn't return data
            delete result.data;
            res.json(result);
        }
    });
}

function updateUserApiHandler(caller, data, req, res) {
    logger.debug('update user');
    chaincodeOps.getUser(caller, data.id, function (err, user) {
        let errmsg;
        if (err != null || !user) {
            errmsg = "User not found";
            logger.error(errmsg, err);
            res.status(404).json({ msg: errmsg, status: 404 });
        } else if (!user.secret) {
            errmsg = "Unauthorized to update the user";
            logger.error(errmsg, err);
            res.status(unauthorizedError).json({ msg: errmsg, status: unauthorizedError });
        } else if (user.role !== data.role) {
            errmsg = "User's role cannot be changed";
            logger.error(errmsg, err);
            res.status(invalidDataError).json({ msg: errmsg, status: invalidDataError });
        } else if (data.secret && user.secret && user.secret !== data.secret) {
            errmsg = "User's secret cannot be changed";
            logger.error(errmsg, err);
            res.status(invalidDataError).json({ msg: errmsg, status: invalidDataError });
        } else {
            logger.debug("Existing User found: ", data.id);
            if (user.secret) {
                data.secret = user.secret;
            }
            registerUser(caller, data, req, res);
        }
    });
}

function getUsersApiHandler(caller, data, req, res) {
    logger.debug('getUsers');
    chaincodeOps.getUsers(caller, data.org, data.role, function (err, users) {
        if (err != null) {
            logger.error(err);
            res.json([]);
        } else {
            res.json(users);
        }
    });
}

function getChainStatApiHandler(caller, data, req, res) {
    logger.debug('chainstat');
    chaincodeOps.chainstat(caller, function (err, stats) {
        if (err != null) {
            var errmsg = "chainstats failed";
            logger.error(errmsg, err);
            res.status(500).json({ msg: errmsg, status: 500 });
        } else {
            logger.debug('chainstat:', stats);
            res.json(stats);
        }
    });
}

function getBlockStatApiHandler(caller, data, req, res) {
    logger.debug('blockstat');
    chaincodeOps.blockstat(caller, data.block_no, function (err, stats) {
        if (err != null) {
            var errmsg = "blockstat failed";
            logger.error(errmsg, err);
            res.status(500).json({ msg: errmsg, status: 500 });
        } else {
            logger.debug('blockstat:', stats);
            res.json(stats);
        }
    });
}

function getLoginTokenByAuthCode(caller, data, req, res) {
    logger.debug('getLoginTokenByAuthCode');
    if (!data.authCode) {
        var errmsg = "Missing auth code in API data";
        logger.error(errmsg);
        res.status(unauthorizedError).json({ msg: errmsg, status: unauthorizedError});
    }

    user_manager.loginByAuthCode(data.authCode, data.timeout, (err, data) => {
        var errmsg = "Failed to get login token";
        if (err != null) {
            logger.error(errmsg);
            res.status(serverError).json({ msg: errmsg, status: serverError});
        } else {
            req.session["token"] = data.token;
            res.json(data);
        }
    });
}

function mergeNetworkConfig(caller, data, req, res) {
    logger.debug('mergeNetworkConfig');
    let networkConfig;
    let errmsg;
    try {
        networkConfig = typeof(data.networkConfig) === 'object' ? data.networkConfig : JSON.parse(data.networkConfig);
    } catch(err) {
        errmsg = "Network Connection Profile's format is incorrect";
        logger.error(errmsg);
        res.status(500).json({ msg: errmsg, status: 500 });
    }

    if (!networkConfig.channels) {
        errmsg = "Missing channels in network connection file";
        logger.error(errmsg);
        res.status(500).json({ msg: errmsg, status: 500 });
    }
    if (!networkConfig.organizations) {
        errmsg = "Missing organizations in network connection file";
        logger.error(errmsg);
        res.status(500).json({ msg: errmsg, status: 500 });
    }
    if (!networkConfig.peers) {
        errmsg = "Missing peers in network connection file";
        logger.error(errmsg);
        res.status(500).json({ msg: errmsg, status: 500 });
    }
    if (!networkConfig.certificateAuthorities) {
        errmsg = "Missing certificate authorities in network connection file";
        logger.error(errmsg);
        res.status(500).json({ msg: errmsg, status: 500 });
    }

    chain_helper.mergeNetworkConfig(networkConfig).then(data => {
        if(data) {
            res.status(200).json(data)
        } else {
            var errmsg = "Failed to get merged network connection file";
            logger.error(errmsg);
            res.status(500).json({ msg: errmsg, status: 500 });
        }
    }, err => {
        var errmsg = "Failed to merge network connection file";
        logger.error(errmsg, err);
        res.status(500).json({ msg: errmsg, status: 500 });
    })
}

module.exports.process_api = process_api;
function process_api(data, req, res) {
    logger.debug('received api:', data.type);
    var enrollId = req.headers["enroll-id"];
    var enrollSecret = req.headers["enroll-secret"];
    var org = req.headers["ca-org"];
    var channel = req.headers["channel"];
    var caller = {
        id: enrollId,
        secret: enrollSecret,
        org: org,
        channel: channel
    };
    try {
        // Process api
        if (data.type === 'getLoginToken') {
            getLoginTokenApiHandler(caller, data, req, res);
        } else if (data.type === 'getRefreshToken') {
            getRefreshTokenApiHandler(caller, data, req, res);
        }

        //orgs
        else if (data.type === 'registerOrg') {
            registerOrgApiHandler(caller, data, req, res);
        } else if (data.type === 'updateOrg') {
            updateOrgApiHandler(caller, data, req, res);
        } else if (data.type === 'getOrgs') {
            getOrgsApiHandler(caller, data, req, res);
        } else if (data.type === 'getOrg') {
            getOrgApiHandler(caller, data, req, res);
        }

        //users
        else if (data.type === 'getUser') {
            getUserApiHandler(caller, data, req, res);
        } else if (data.type === 'registerUser') {
            registerUserApiHandler(caller, data, req, res);
        } else if (data.type === 'putUserInOrg') {
            putUserInOrgApiHandler(caller, data, req, res);
        } else if (data.type === 'updateUser') {
            updateUserApiHandler(caller, data, req, res);
        } else if (data.type === 'updateLoginUser') {
            updateLoginUserApiHandler(caller, data, req, res);
        } else if (data.type === 'getUsers') {
            getUsersApiHandler(caller, data, req, res);
        }

        //chain
        else if (data.type === 'getChainStat') {
            getChainStatApiHandler(caller, data, req, res);
        } else if (data.type === 'getBlockStat') {
            getBlockStatApiHandler(caller, data, req, res);
        }

        // mfa
        else if (data.type === 'getLoginTokenByAuthCode') {
            getLoginTokenByAuthCode(caller, data, req, res);
        } else if (data.type === 'mergeNetworkConfig') {
            mergeNetworkConfig(caller, data, req, res);
        }

        else {
            var errmsg = "Unknown API end point";
            logger.error(errmsg, data.type);
            res.status(404).json({ msg: errmsg + req.path, status: 404 });
        }
    } catch (err) {
        var errmsg = "process api error";
        logger.error(errmsg, err);
        res.status(500).json({ msg: errmsg, status: 500 });
    }
};
