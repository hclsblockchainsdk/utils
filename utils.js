/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/
"use strict";

var TAG = "utils.js";
var hfc = require('fabric-client');
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;
const child_process = require('child_process');

module.exports.setup = function () {
};

module.exports.callExternalFunctionLocal = callExternalFunctionLocal;
function callExternalFunctionLocal(sys_user, cmd, mode) {
	var expendedCmd = "sudo -H -u " + sys_user + " bash -c \'" + cmd + "\'";
	try  {
		if (mode == 'sync') {
			child_process.execSync(expendedCmd, (err, stdout, stderr) => {
				if (err) {
					logger.info(err);
					return;
				}
				logger.info(stdout);
				logger.info(stderr);
			});
		}
		else {
			logger.info("mode other than sync is not supported now.");
			throw new Error("mode other than sync is not supported now.");
		}
	}
	catch (error) {
		console.log("Something wrong with exit code: " + error.status)
		return error.status;
	}
	return 0;
}