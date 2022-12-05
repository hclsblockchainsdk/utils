/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

const Redis = require('ioredis');
const hfc = require('fabric-client');
const log4js = require('log4js');

const log = log4js.getLogger('Redis-Service');
log.level = hfc.getConfigSetting('log_level') || 'info';

const config = hfc.getConfigSetting('redisService') || {};

const createRedisClient = () => {
  if (config.enabled) {
    log.info('Initiate Redis Service connection');
    if (process.env.REDIS_URL) {
      return new Redis(process.env.REDIS_URL);
    } else {
      return new Redis(config.port, config.host);
    } 
  }

  log.info('Redis Service is disabled');

  return null;
};

const client = createRedisClient();

/**
 * Retrieve data from Redis cache.
 *
 * @param key - unique key
 * @returns {Promise<String>} data from Redis cache by the provided key
 */
const getData = async (key) => {
  if (!config.enabled) {
    throw new Error('Redis service is disabled.');
  }

  if (!key) {
    throw new Error('Cannot retrieve data from Redis without the key.');
  }

  try {
    return client.get(key);
  } catch (e) {
    throw new Error(`Unable to retreive data from Redis cache. Error: ${e}`);
  }
};

/**
 * Save data to Redis cache.
 *
 * @param {String} key - unique key
 * @param {String|Number} data - data to save in cache
 */
const setData = async (key, data) => {
  if (!config.enabled) {
    throw new Error('Redis service is disabled.');
  }

  if (!key) {
    throw new Error('Missing key to save in Redis cache.');
  }
  if (!data) {
    throw new Error('Missing data to save in Redis cache.');
  }

  try {
    await client.setex(key, config.cacheExpiration, data);
  } catch(e) {
    throw new Error(`Unable to save data to Redis cache. Error: ${e}`);
  }
};

module.exports = { getData, setData };
