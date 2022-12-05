/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

const sendGrid = require('@sendgrid/mail');
class EmailService {
    /**
     * Wrapper for sendgrid email API.
     *
     * @param config {sendgrid: {SENDGRID_API_KEY}}
     * Only the API key is required.
     */
    constructor(config){
        if(!config){
            throw new Error("A config object is required");
        }
        if(!config.sendgrid){
            throw new Error("The sendgrid property in the config is required");
        }
        if(!config.sendgrid.SENDGRID_API_KEY) {
            throw new Error("Missing SENDGRID_API_KEY");
        }
        try {
            this.config = config;
            sendGrid.setApiKey(config.sendgrid.SENDGRID_API_KEY);
        } catch (err) {
            throw err;
        }
    }

    /**
     * Send one or more messages
     * @param message - An object defined in https://github.com/sendgrid/sendgrid-nodejs/blob/master/use-cases/README.md
     * @returns {Promise<[ClientResponse, {}]>}
     */
    async send(message){
        return await sendGrid.send(message);
    }

}
module.exports = EmailService;