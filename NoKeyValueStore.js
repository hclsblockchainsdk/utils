/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

'use strict';

var api = require('fabric-client/lib/api.js');
var fs = require('fs-extra');
var path = require('path');
var utils = require('fabric-client/lib/utils');
var hfc = require('fabric-client');

var log4js = require('log4js');
var logger = log4js.getLogger("NoKeyValueStore");
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

/**
 * This is a default implementation of the [KeyValueStore]{@link module:api.KeyValueStore} API.
 * It uses files to store the key values.
 *
 * @class
 * @extends module:api.KeyValueStore
 */
var FileKeyValueStore = class extends api.KeyValueStore {

	/**
	 * constructor
	 *
	 * @param {Object} options contains a single property <code>path</code> which points to the top-level directory
	 * for the store
	 */
	constructor(options) {
		logger.debug('constructor', { options: options });

		if (!options || !options.path) {
			throw new Error('Must provide the path to the directory to hold files for the store.');
		}

		// Create the keyValStore instance
		super();

		var self = this;
		this._dir = options.path;
		return new Promise(function (resolve, reject) {
			fs.mkdirs(self._dir, function (err) {
				if (err) {
					logger.error('constructor, error creating directory, code: %s' , err.code);
					return reject(err);
				}
				return resolve(self);
			});
		});
	}

	getValue(name) {
		logger.debug('getValue', { key: name });

		var self = this;

		return new Promise(function (resolve, reject) {
			var p = path.join(self._dir, name);
			return resolve(null);
		});
	}

	setValue(name, value) {
		logger.debug('setValue', { key: name });

		var self = this;

		return new Promise(function (resolve, reject) {
			var p = path.join(self._dir, name);
			return resolve(value);
		});
	}
};

module.exports = FileKeyValueStore;
