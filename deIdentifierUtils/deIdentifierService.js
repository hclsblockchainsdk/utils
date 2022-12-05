/*
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 */

/*
 * File with util functions to interact with De-Identifier service API.
 * De-Identifier service is an external service.
 * It used to de-identify PHI/PII data
 * and store these data in specified HIPAA compliant storage.
 *
 * @see https://github.com/HCLS-Consent-Manager/de-identifier/
 */

const log4js = require('log4js');
const axios = require('axios');
const hfc = require('fabric-client');
const chainHelper = require('common-utils/chain_helper');
const { getData, setData } = require('common-utils/cache/redisService');

const deIdentifierConfig = hfc.getConfigSetting('de_identifier');
const isDeIdentifierServiceEnabled = deIdentifierConfig && deIdentifierConfig.enabled;
const baseUrl = isDeIdentifierServiceEnabled && `${deIdentifierConfig.host}:${deIdentifierConfig.port}`;

const identifierRoute = '/api/identifier';
const deIdentifierRoute = '/api/de-identifier';
const searchDePiiRoute = '/api/de-identifier/search';
const authorizeRoute = '/api/authorize';

const log = log4js.getLogger('deIdentifierUtils');
log.level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";

log.info(`PII/PHI de-identification is ${isDeIdentifierServiceEnabled ? 'enabled' : 'disabled'}`);

if (isDeIdentifierServiceEnabled) log.debug('De-identifier config:', deIdentifierConfig);

/**
 * De-identify PII/PHI.
 * If de-identification is disabled
 * then returns PII without de-identification.
 *
 * @param {string} pii - PII/PHI
 * @returns {string} De-PII/PHI key if de-identification is enabled otherwise PII/PHI
 */
module.exports.deIdentifyPii = async (pii) => {
  log.debug('Request to de-identify PII');

  try {
    const url = baseUrl + deIdentifierRoute;
    const response = await sendPostRequest(url, { pii });
    log.debug('De-identification successful');
    return response.data.dePii;
  } catch (err) {
    log.error('Failed to de-identify PII', err.message);
    throw err;
  }
};

/**
 * Search for existing de-identified PII record on De-Identifier service.
 * If record does not exist return null.
 *
 * @param {string} pii - PII/PHI data
 * @returns {Promise<string>} de-identified PII record if it exists otherwise null
 */
module.exports.getDeIdentifiedPii = async (pii) => {
  log.debug('Search for de-identified PII');

  try {
    const url = baseUrl + searchDePiiRoute;
    const response = await sendPostRequest(url, { pii });
    return response.data.dePii;
  } catch (err) {
    log.error('Failed to de-identify PII', err.message);
    throw err;
  }
};

/**
 * Identify PII/PHI by De-PII key.
 * If de-identification is disabled then returns same value
 * that was passed as dePii argument.
 *
 * @param {string} dePii - de-identified PII/PHI key
 * @returns {string} PII/PHI
 */
module.exports.getPii = async (dePii) => {
    log.debug('Try to identify PII for De-PII');

    try {
      const url = baseUrl + identifierRoute;
      const response = await sendPostRequest(url, { dePii });
      return response.data.pii;
    } catch (err) {
      log.error('Failed to identify PII.', err.message);
      throw err;
    }
};

/**
 * Send post request with axios.
 *
 * @param {string} url - URL
 * @param {object} data - data to send
 * @returns {Promise<AxiosResponse<object>>} axios response.
 */
async function sendPostRequest(url, data) {
  log.debug(`Send post request to De-Identifier service. URL: ${url}`);
  try {
    const token = await getAuthToken();
    return await axios.post(url, data, {
      headers: { 'X-Auth-Token':  token }
    });
  } catch (err) {
    log.trace(err);

    if (err.response) {
      const responseData = err.response.data;
      throw new Error(`Request to De-identifier service is failed. Status:\n${responseData.status}, message: ${responseData.message}`);
    }

    if (err.request) {
      throw new Error(`Failed to send request to De-identifier service.\n${err.message}`);
    }

    throw err;
  }
}

const tokenCacheKey = 'deIdentifierAuthToken';
const tokenExpirationCacheKey = 'deIdentifierAuthTokenExpiration';

/**
 * Function returns authorization token to access protected resources
 * on De-Identifier service. If token is not received yet or is expired
 * then request new token.
 *
 * @returns {Promise<String>} authorization token for De-Identifier service
 */
const getAuthToken = async () => {
  try {
    let token = await getData(tokenCacheKey);
    let tokenExpiration = await getData(tokenExpirationCacheKey);

    if (!token || isTokenExpired(tokenExpiration)) {
      log.debug('Request new authorization token for De-Identifier service');
      token = await authorize();
      tokenExpiration = getTokenExpirationTime(token);

      await setData(tokenCacheKey, token);
      await setData(tokenExpirationCacheKey, tokenExpiration);
    }

    return token;
  } catch (e) {
    throw new Error(`Unable to get Authorization token. Error:  ${e}`);
  }
};

/**
 * Get token expiration timestamp from JWT token.
 *
 * @param {String} token - JWT token.
 * @returns {Number} - timestamp when JWT expires.
 */
function getTokenExpirationTime(token) {
  const splitToken = token.split('.');
  const encodedTokenPayload = splitToken[1];
  const decodedPayloadString = Buffer.from(encodedTokenPayload, 'base64').toString('utf-8');
  const decodedPayload = JSON.parse(decodedPayloadString);

  return decodedPayload.exp;
}

/**
 * Check if token is expired.
 *
 * @param {Number} tokenExpirationTimestamp - token expiration timestamp in seconds
 * @returns {Boolean} true if token is expired otherwise false.
 */
function isTokenExpired(tokenExpirationTimestamp) {
  const currentTimestamp = Math.floor(Date.now() / 1000);
  return currentTimestamp >= tokenExpirationTimestamp;
}

/**
 * Get credentials to authorize on De-Identifier service.
 *
 * @returns {{userId: String, secret: String}} auth credentials
 */
function getAuthCredentials() {
  // TODO: this code is for owner-mediated-records solution and will be reworked in scope of WHHUNSDK-311
  const defaultSolutionConfig = chainHelper.solutionConfig();
  const omrAdminUser = defaultSolutionConfig['solutions']['owner-mediated-records']['app_admin'];

  return { userId: omrAdminUser.username, secret: omrAdminUser.secret };
}

/**
 * Send authorization request to De-Identifier service.
 *
 * @returns {Promise<String>} authorization token
 */
async function authorize() {
  log.debug(`Authorize on De-Identifier service`);

  try {
    const url = baseUrl + authorizeRoute;
    const authCredentials = getAuthCredentials();

    const response = await axios.post(url, authCredentials);

    log.debug('Successfully received authorization token from De-Identifier service');

    return response.data.token;
  } catch (err) {
    log.error('Failed to authorize on De-Identifier service', err.message);
    throw err;
  }
}
