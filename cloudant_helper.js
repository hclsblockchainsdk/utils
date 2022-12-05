/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

'use strict';

const Cloudant = require('@cloudant/cloudant');
const hfc = require('fabric-client');
const log4js = require('log4js');
const fs = require('fs-extra');
const TAG = 'cloudant_helper.js';
const logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : 'INFO';
logger.level = log_level;

function CloudantHelper(username, password, dbName, host = '') {
    let initOptions = {
        account: username,
        password: password,
        maxAttempt: 5,
        plugins: {
            retry: {
                retryErrors: false
            }
        }
    };

    // use host if one is specified
    if (host) {
        initOptions['url'] = host
    }

    try {
        let cloudant = Cloudant(initOptions);
        let db = cloudant.use(dbName);
        this.cloudantDB = db;
    } catch (err) {
        const errMsg = 'Failed to initialize Cloudant DB: ' + dbName;
        logger.error(errMsg, err);
        return '';
    }
}

CloudantHelper.prototype.createDocument = function (docID, doc) {
    logger.debug('Creating document ' + docID);
    return new Promise((resolve, reject) => {
        this.cloudantDB.insert(
            doc
                ? {
                      _id: docID,
                      doc: doc
                  }
                : {
                      _id: docID
                  },
            (err, result) => {
                if (err) {
                    const errMsg = 'Failed to create document ' + docID;
                    logger.error(errMsg, err);
                    reject(err);
                } else {
                    logger.debug('Created document successfully:', result);
                    resolve(result);
                }
            }
        );
    });
};

CloudantHelper.prototype.insertAttachment = function (docID, docRev, filePath, fileName, fileType) {
    logger.debug('Insert attachment to document ' + docID);
    return new Promise((resolve, reject) => {
        let errMsg;
        fs.readFile(filePath, (err, fileData) => {
            if (!err) {
                this.cloudantDB.attachment.insert(
                    docID,
                    fileName,
                    fileData,
                    fileType,
                    {
                        rev: docRev
                    },
                    (err, result) => {
                        if (!err) {
                            logger.debug('Insert attachment successfully ', result);
                            resolve(result);
                        } else {
                            errMsg = 'Failed to upload the file ' + filePath;
                            logger.error(errMsg, err);
                            reject(err);
                        }
                    }
                );
            } else {
                errMsg = 'Failed to upload the file ' + filePath;
                logger.error(errMsg, err);
                reject(err);
            }
        });
    });
};

CloudantHelper.prototype.getAttachment = function (docID, fileName) {
    logger.debug('Get attachment from document ' + docID);
    return new Promise((resolve, reject) => {
        this.cloudantDB.attachment.get(docID, fileName, (err, result) => {
            if (!err) {
                logger.debug(
                    `Get the attachment ${fileName} successfully \n` + JSON.stringify(result)
                );
                resolve(result);
            } else {
                let errMsg = 'Failed to get the attachment ' + fileName;
                logger.error(errMsg, err);
                reject(err);
            }
        });
    });
};

CloudantHelper.prototype.deleteAttachment = function (docID, docRev, fileName) {
    logger.debug('Delete attachment from document ' + docID);
    return new Promise((resolve, reject) => {
        this.cloudantDB.attachment.destroy(
            docID,
            fileName,
            {
                rev: docRev
            },
            (err, result) => {
                if (!err) {
                    logger.debug(`Delete the attachment ${fileName} successfully`);
                    resolve(result);
                } else {
                    errMsg = 'Failed to delete the attachment ' + fileName;
                    logger.error(errMsg, err);
                    reject(err);
                }
            }
        );
    });
};

CloudantHelper.prototype.readDocument = function (docID) {
    logger.debug('Reading document ' + docID);
    return new Promise((resolve, reject) => {
        this.cloudantDB.get(docID, (err, result) => {
            if (err) {
                const errMsg = 'Failed to read document ' + docID;
                logger.error(errMsg, err);
                reject(err);
            } else {
                logger.debug('Read document successfully:', result);
                resolve(result);
            }
        });
    });
};

CloudantHelper.prototype.updateDocument = function (docID, docRev, doc) {
    logger.debug('Updating document ' + docID);
    return new Promise((resolve, reject) => {
        this.cloudantDB.insert({
                _id: docID,
                _rev: docRev,
                doc: doc
            },
            (err, result) => {
                if (err) {
                    const errMsg = 'Failed to update document ' + docID;
                    logger.error(errMsg, err);
                    reject(err);
                } else {
                    logger.debug('Updated document successfully:', result);
                    resolve(result);
                }
            }
        );
    });
};

CloudantHelper.prototype.deleteDocument = function (docID, docRev) {
    logger.debug('Deleting document ' + docID);
    return new Promise((resolve, reject) => {
        this.cloudantDB.destroy(docID, docRev, (err, result) => {
            if (err) {
                var errMsg = 'Failed to delete document ' + docID;
                logger.error(errMsg, err);
                reject(err);
            } else {
                logger.debug('Deleted document successfully:', result);
                resolve(result);
            }
        });
    });
};

CloudantHelper.prototype.listDocuments = function () {
    logger.debug('Listing all documents');
    return new Promise((resolve, reject) => {
        this.cloudantDB.list((err, result) => {
            if (err) {
                const errMsg = 'Failed to list all documents';
                logger.error(errMsg, err);
                reject(err);
            } else {
                logger.debug('List all documents successfully');
                resolve(result);
            }
        });
    });
};

module.exports = CloudantHelper;
