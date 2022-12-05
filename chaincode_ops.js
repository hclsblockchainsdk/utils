/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

'use strict';

// For logging
var TAG = 'chaincode_ops:';
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);

var util = require('util');
var hfc = require('fabric-client');
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

var helper = require('../utils/chain_helper.js');

var solutionConfig = {};
var chaincodeName = null;

const roles = {
    USER: 'user',
    ORG: 'org',
    AUDIT: 'audit',
    SYSTEM: 'system'
};

module.exports = {roles: roles};

module.exports.setup = function (config) {
    solutionConfig = config;
    chaincodeName = solutionConfig && solutionConfig["chaincode"] ? solutionConfig["chaincode"]["name"] : "";
    logger.info("chaincodeName:", chaincodeName);
};

/**
 * Get a login user
 * @param caller The user submitting the transaction.
 * @param userId Login User Id
 */
module.exports.getLoginUser = getLoginUser;
function getLoginUser(caller, userId, cb) {
    logger.debug('get login user:', userId);

    let fcn = 'getLoginUser';
    let args = [userId];

    query(caller, fcn, args, function(err, result) {
        if(err) {
            var errmsg = "Failed to get login user";
            logger.error(errmsg, err);
            try {
                cb && cb(new Error(errmsg));
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
        else {
            logger.debug('got login user successfully:', result);
            try {
                cb && cb(null, result);
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
    });
}

/**
 * Invoke test
 * @param caller The user submitting the transaction.
 */
module.exports.invokeTest = invokeTest;
function invokeTest(caller, cb) {
    logger.debug('invoke test:');

    let fcn = 'invokeTest';
    let args = [caller.id, caller.secret];

    invoke(caller, fcn, args, function(err, result) {
        if(err) {
            var errmsg = "Failed invoke test";
            logger.error(errmsg, err);
            cb && cb(new Error(errmsg));
        }
        else {
            logger.debug('invoke test successful:', result);
            cb && cb(null, result);
        }
    });
}

/**
 * Query test
 * @param caller The user submitting the transaction.
 */
module.exports.queryTest = queryTest;
function queryTest(caller, cb) {
    logger.debug('query test');

    let fcn = 'queryTest';
    let args = [caller.id, caller.secret];

    query(caller, fcn, args, function(err, value) {
        if(err) {
            var errmsg = "Failed query test";
            logger.error(errmsg, err);
            cb && cb(new Error(errmsg));
        }
        else {
            logger.debug('query test successful:', value);
            cb && cb(null, value);
        }
    });
}

/**
 * Register a org
 * @param caller The user submitting the transaction.
 * @param orgInfo JSON
 */
module.exports.registerOrg = registerOrg;
function registerOrg(caller, orgInfo, cb) {
    logger.debug('Register org:', orgInfo.id);

    var makeCallerAdmin = "false";
    var args = [];

    var orgInfoStr = "";
    try {
        orgInfoStr = JSON.stringify(orgInfo);
    } catch (err) {
        var errmsg = "Invalid org info";
        logger.error(errmsg, err);
        cb && cb(new Error(errmsg));
        return;
    }

    args.push(orgInfoStr, makeCallerAdmin);

    var fcn = "registerOrg";

    if (orgInfo.role != "org"){
        cb && cb(new Error('Invalid org role: '+orgInfo.role));
    } else {
        invoke(caller, fcn, args, function(err, result) {
            if(err) {
                var errmsg = "Failed to register org";
                logger.error(errmsg, err);
                try {
                    cb && cb(new Error(errmsg));
                } catch(err) {
                    logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
                }
            }
            else {
                logger.debug('Registered org successfully');
                try {
                    cb && cb(null, result);
                } catch(err) {
                    logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
                }
            }
        });
    }
}

/**
 * Get all orgs
 * @param caller The user submitting the transaction.
 */
module.exports.getOrgs = getOrgs;
function getOrgs(caller, cb) {
    logger.debug('get orgs');

    let fcn = 'getOrgs';
    let args = [];


    query(caller, fcn, args, function(err, result) {
        if(err) {
            var errmsg = "Failed to get orgs";
            logger.error(errmsg, err);
            try {
                cb && cb(new Error(errmsg));
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
        else {
            logger.debug('got orgs successfully');
            try {
                cb && cb(null, result);
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
    });
};

/**
 * Get an org
 * @param caller The user submitting the transaction.
 * @param orgId Id of org
 */
module.exports.getOrg = getOrg;
function getOrg(caller, orgId, cb) {
    logger.debug('get org:', orgId);

    let fcn = 'getOrg';
    let args = [orgId];

    query(caller, fcn, args, function(err, value) {
        if(err) {
            var errmsg = "failed to get org:";
            logger.error(errmsg, err);
            try {
                cb && cb(new Error(errmsg));
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
        else {
            logger.debug('got org successfully');
            try {
                cb && cb(null, value);
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
    });
}

/**
 * Update organization
 * @param caller The user submitting the transaction.
 * @param org Org object
 */
module.exports.updateOrg = updateOrg;
function updateOrg(caller, orgData, cb) {
    logger.debug('Update org', orgData.id);

    var org = {
        id: orgData.id,
        name: orgData.name,
        data: orgData.data
    };

    let fcn = 'updateOrg';
    let args = [JSON.stringify(org)];

    invoke(caller, fcn, args, function(err, result) {
        if(err) {
            var errmsg = "Failed to update org";
            logger.error(errmsg, err);
            try {
                cb && cb(new Error(errmsg));
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
        else {
            logger.debug('Updated org successfully');
            try {
                cb && cb(null, result);
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
    });
}

/**
 * Register a user
 * @param caller The user submitting the transaction.
 * @param userInfo JSON
 */
module.exports.registerUser = registerUser;
function registerUser(caller, userInfo, cb) {
    logger.debug('Register user', userInfo.id);

    var giveAccessToCaller = "false";
    var args = [];

    var userInfoStr = "";
    try {
        userInfoStr = JSON.stringify(userInfo);
    } catch (err) {
        var errmsg = "Invalid user info";
        logger.error(errmsg, err);
        cb && cb(new Error(errmsg));
        return;
    }

    var fcn = "";
    if (userInfo.role === roles.USER) {
        fcn = "registerUser";
    } else if (userInfo.role === roles.SYSTEM) {
        fcn = "registerSystemAdmin";
    } else if (userInfo.role === roles.AUDIT) {
        fcn = "registerAuditor";
    } else if (userInfo.role === roles.ORG) {
        fcn = "registerOrgAdmin";
    }
    args.push(userInfoStr, giveAccessToCaller);
    if (fcn === ""){
        cb && cb(new Error('Invalid user role: '+userInfo.role));
    } else {
        invoke(caller, fcn, args, function(err, result) {
            if(err) {
                var errmsg = "Failed to register user";
                logger.error(errmsg, err);
                try {
                    cb && cb(new Error(errmsg));
                } catch(err) {
                    logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
                }
            }
            else {
                logger.debug('Register User succeeded');
                try {
                    cb && cb(null, result);
                } catch(err) {
                    logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
                }
            }
        });
    }
}

/**
 * Get users
 * @param caller The user submitting the transaction.
 * @param orgId org id
 * @param role  user role (optional)
 */
module.exports.getUsers = getUsers;
function getUsers(caller, orgId, role, cb) {
    logger.debug('get users for:', orgId, role);

    var fcn = 'getUsers';
    var args = [orgId, role];

    query(caller, fcn, args, function(err, value) {
        if(err) {
            var errmsg = "Failed to get users:";
            logger.error(errmsg, err);
            try {
                cb && cb(new Error(errmsg));
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
        else {
            logger.debug('got result for get users');
            try {
                cb && cb(null, value);
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
    });
}


/**
 * Get a user
 * @param caller The user submitting the transaction.
 */
module.exports.getUser = getUser;
function getUser(caller, userId, cb) {
    logger.debug('get user:', userId);

    var fcn = 'getUser';
    var args = [userId];

    query(caller, fcn, args, function(err, value) {
        if(err) {
            var errmsg = "Failed to get user";
            logger.error(errmsg, err);
            try {
                cb && cb(new Error(errmsg));
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
        else {
            logger.debug('retrieved user');
            try {
                cb && cb(null, value);
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
    });
}

/**
 * Put user in group
 * @param caller The user submitting the transaction.
 */
module.exports.putUserInOrg = putUserInOrg;
function putUserInOrg(caller, userID, orgID, isAdmin, cb) {
    logger.debug('Put user in group:', userID, orgID, isAdmin);

    var fcn = 'putUserInOrg';
    var args = [userID, orgID, isAdmin];

    invoke(caller, fcn, args, function (err, result) {
        if (err) {
            var errmsg = "Failed to put user in group";
            logger.error(errmsg, err);
            try {
                cb && cb(new Error(errmsg));
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
        else {
            logger.debug('Put user in group successfully');
            try {
                cb && cb(null, result);
            } catch(err) {
                logger.error(util.format("callback for "+fcn+" failed: error: %s", err));
            }
        }
    });
}

/**
 * chainstat
 * @param caller The user submitting the transaction.
 */
module.exports.chainstat = chainstat;
function chainstat(caller, cb) {
    logger.debug('chainstat');

    helper.getChainInfo(caller.id, caller.secret, caller.org, caller.channel)
        .then((chainInfo) => {
            cb && cb(null, chainInfo);
        }, (err) => {
            var errmsg = "Failed to get chainstat";
            logger.error(errmsg, err);
            cb && cb(new Error(errmsg));
        });
}

/**
 * blockstat
 * @param caller The user submitting the transaction.
 */
module.exports.blockstat = blockstat;
function blockstat(caller, blockNumber, cb) {
    logger.debug('blockstat:', blockNumber);

    helper.getBlockByNumber(blockNumber, caller.id, caller.secret, caller.org, caller.channel)
        .then((block) => {
            cb && cb(null, block);
        }, (err) => {
            var errmsg = "Failed to get block";
            logger.error(errmsg, err);
            cb && cb(new Error(errmsg));
        });
}

/**
 * Helper function for invoking chaincode using the hfc SDK.
 * @param cb A callback of the form: function(error, invoke_result)
 */

function invoke (caller, fcn, args, cb) {
    helper.invoke(caller.id, caller.secret, caller.channel, chaincodeName, fcn, args, null, caller.org).then((response) => {
        try{
            cb(null, response);
        } catch (err) {
            logger.error("callback of invoke failed: ", err);
        }
        return;
    }).catch((err) => {
        logger.error(util.format("invoke "+fcn+" failed: error: %s", err));
        try {
            cb && cb(err, null);
        } catch(err) {
            logger.error("callback of invoke failed: ", err);
        }
        return;
    });
}

module.exports._invoke = invoke;

function invokePHI (caller, fcn, args, phi_args, cb) {
    helper.invokePHI(caller.id, caller.secret, caller.channel, chaincodeName, fcn, args, phi_args, null, caller.org).then((response) => {
        try{
            cb(null, response);
        } catch (err) {
            logger.error("callback of invoke failed: ", err);
        }
        return;
    }).catch((err) => {
        logger.error(util.format("invoke "+fcn+" failed: error: %s", err));
        try {
            cb && cb(err, null);
        } catch(err) {
            logger.error("callback of invoke failed: ", err);
        }
        return;
    });
}

module.exports._invokePHI = invokePHI;

/**
 * Helper function for querying chaincode using the hfc SDK.
 * @param cb A callback of the form: function(error, queried_data)
 */

function query (caller, fcn, args, cb) {
    helper.query(caller.id, caller.secret, caller.channel, chaincodeName, fcn, args, null, caller.org).then((value) => {
        try{
            cb(null, value);
        } catch (err) {
            logger.error("callback of query failed: ", err);
        }
        return;
    }).catch((err) => {
        logger.error(util.format("query "+fcn+" failed: error: %s", err));
        try {
            cb && cb(err, null);
        } catch(err) {
            logger.error("callback of query failed: ", err);
        }
        return;
    });
}

module.exports._query = query;
