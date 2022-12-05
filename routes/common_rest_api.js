/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/

let crypto = require("crypto");
let express = require('express');
let hfc = require('fabric-client');
let request = require("request");
let session = require("cookie-session");

let kms = require('../kms.js');
let route_login = require('../routes/route_login.js');

// original API handler is here. Transform original api handler to common handler
let req_handler = require('../request_handler.js');

// Use tags to make logs easier to find
let TAG = "common_rest_api.js";
let log4js = require('log4js');
let logger = log4js.getLogger(TAG);
let log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

const invalidDataError = 400;
const unauthorizedError = 401;
const common_api_base = '/common/api/v1';

let router = express.Router();

// use secure session cookies
// todo: should the secret be more robust?
router.use(
  session({
    secret: "Somethignsomething1234!test",
    cookie: {
      httpOnly: true,
      secure: true
    }
  })
);

// 1. if path is /login or /mfa skip authentication,
// 2. check token
// 3. if authorization (basic auth) exist in headers, remove token in session
// 4. check token in session
// 5. check headers
// 6. apilogin (require same headers as login) - basic auth first and then headers
router.use(function(req, res, next) { route_login.login(req, res, next); });


//===========================================
// data definitions
//===========================================

/**
 * @swagger
 * definitions:
 *   LoginResponse:
 *     properties:
 *       id:
 *         type: string
 *       name:
 *         type: string
 *       secret:
 *         type: string
 *       msg:
 *         type: object
 *         properties:
 *           result:
 *             type: string
 *           error:
 *             type: string
 *       token:
 *         type: string
 *       public_key:
 *         type: string
 *   SignData:
 *     properties:
 *       user_id:
 *         type: string
 *         default: ""
 *       method:
 *         type: string
 *         enum: ["GET", "POST", "PUT"]
 *         default: "GET"
 *       api_path:
 *         type: string
 *         default: "/api/v1/"
 *       sign_key:
 *         type: string
 *         default: ""
 *       sign_algorithm:
 *         type: string
 *         default: "sha256"
 *       payload:
 *         type: object
 *         default: ""
 *       is_proxy:
 *         type: boolean
 *         default: false
 *       encrypt_payload:
 *         type: boolean
 *         default: false
 *   OrgNew:
 *     properties:
 *       id:
 *         type: string
 *         default: "required"
 *       secret:
 *         type: string
 *         default: "optional (required if already registered in CA)"
 *       name:
 *         type: string
 *         default: "required"
 *       ca_org:
 *         type: string
 *         default: "required"
 *       email:
 *         type: string
 *         default: "required"
 *       tax_id:
 *         type: string
 *         default: "required"
 *       address:
 *         type: string
 *         default: "required"
 *       role:
 *         $ref: '#/definitions/SolutionLevelRole'
 *         default: "org"
 *       data:
 *         type: object
 *         default: {}
 *       status:
 *         type: string
 *         default: "active"
 *       public_key:
 *         type: string
 *         default: ""
 *       private_key:
 *         type: string
 *         default: ""
 *       sym_key:
 *         type: string
 *         default: ""
 *       verify_key:
 *         type: string
 *         default: ""
 *   OrgUpdate:
 *     properties:
 *       id:
 *         type: string
 *         default: "required"
 *       name:
 *         type: string
 *         default: "required"
 *       ca_org:
 *         type: string
 *         default: "required"
 *       tax_id:
 *         type: string
 *         default: "required"
 *       address:
 *         type: string
 *         default: "required"
 *       role:
 *         $ref: '#/definitions/SolutionLevelRole'
 *         default: "org"
 *       data:
 *         type: object
 *         default: {}
 *       status:
 *         type: string
 *         default: "active"
 *   Org:
 *     properties:
 *       id:
 *         type: string
 *       name:
 *         type: string
 *       role:
 *         type: string
 *       public_key:
 *         type: string
 *       private_key:
 *         type: string
 *       sym_key:
 *         type: string
 *       IsGroup:
 *         type: boolean
 *       status:
 *         type: string
 *       email:
 *         type: string
 *       kms_public_key_id:
 *         type: string
 *       kms_private_key_id:
 *         type: string
 *       kms_sym_key_id:
 *         type: string
 *       secret:
 *         type: string
 *       data:
 *         type: object
 *   OrgResponse:
 *     properties:
 *       id:
 *         type: string
 *       key_id:
 *         type: object
 *       secret:
 *         type: string
 *       msg:
 *         type: object
 *         properties:
 *           result:
 *             type: string
 *           error:
 *             type: string
 *   UserNew:
 *     properties:
 *       id:
 *         type: string
 *         default: "required"
 *       secret:
 *         type: string
 *         default: "optional (required if already registered in CA)"
 *       name:
 *         type: string
 *         default: "required"
 *       email:
 *         type: string
 *         default: "required"
 *       ca_org:
 *         type: string
 *         default: "required"
 *       role:
 *         $ref: '#/definitions/SolutionLevelRole'
 *       data:
 *         type: object
 *         default: {}
 *       public_key:
 *         type: string
 *         default: ""
 *       private_key:
 *         type: string
 *         default: ""
 *       sym_key:
 *         type: string
 *         default: ""
 *       verify_key:
 *         type: string
 *         default: ""
 *   UserUpdate:
 *     properties:
 *       id:
 *         type: string
 *         default: "required"
 *       name:
 *         type: string
 *         default: "required"
 *       ca_org:
 *         type: string
 *         default: "required"
 *       role:
 *         $ref: '#/definitions/SolutionLevelRole'
 *       data:
 *         type: object
 *         default: {}
 *       status:
 *         type: string
 *         default: "active"
 *   LoginUserUpdate:
 *     properties:
 *       id:
 *         type: string
 *       name:
 *         type: string
 *       password:
 *         type: string
 *       email:
 *         type: string
 *       data:
 *         type: object
 *         default: {}
 *   User:
 *     properties:
 *       id:
 *         type: string
 *       name:
 *         type: string
 *       role:
 *         type: string
 *         enum: ["user", "org", "audit", "system"]
 *         default: "user"
 *       is_group:
 *         type: boolean
 *         default: false
 *       email:
 *         type: string
 *       data:
 *         type: object
 *         default: {}
 *       status:
 *         type: string
 *         default: "active"
 *       public_key:
 *         type: string
 *       private_key:
 *         type: string
 *       sym_key:
 *         type: string
 *       kms_private_key_id:
 *         type: string
 *       kms_public_key_id:
 *         type: string
 *       kms_sym_key_id:
 *         type: string
 *       secret:
 *         type: string
 *   SimpleUser:
 *     properties:
 *       id:
 *         type: string
 *       name:
 *         type: string
 *       role:
 *         type: string
 *         enum: ["user", "org", "audit", "system"]
 *         default: "user"
 *       is_group:
 *         type: boolean
 *         default: false
 *       status:
 *         type: string
 *         default: "active"
 *       public_key:
 *         type: string
 *   UserResponse:
 *     properties:
 *       id:
 *         type: string
 *       key_id:
 *         type: object
 *       secret:
 *         type: string
 *       msg:
 *         type: object
 *         properties:
 *           result:
 *             type: string
 *           error:
 *             type: string
 *       token:
 *         type: string
 *   Log:
 *     properties:
 *       transaction_id:
 *         type: string
 *       namespace:
 *         type: string
 *       function_name:
 *         type: string
 *       caller_id:
 *         type: string
 *       data:
 *         type: object
 *       timestamp:
 *         type: integer
 *         format: int64
 *   NetworkConfig:
 *     properties:
 *       networkConfig:
 *         type: object
 *         default: {}
 *   ChainStat:
 *     properties:
 *       height:
 *         type: object
 *         properties:
 *           low:
 *             type: integer
 *             format: int64
 *           high:
 *             type: integer
 *             format: int64
 *           unsigned:
 *             type: boolean
 *       currentBlockHash:
 *         type: object
 *         properties:
 *           buffer:
 *             type: object
 *             properties:
 *               type:
 *                 type: string
 *               data:
 *                 type: array
 *                 items:
 *                   type: integer
 *                   format: int64
 *           offset:
 *             type: integer
 *             format: int64
 *           markedOffset:
 *             type: integer
 *             format: int64
 *           limit:
 *             type: integer
 *             format: int64
 *           littleEndian:
 *             type: boolean
 *           noAssert:
 *             type: boolean
 *       previousBlockHash:
 *         type: object
 *         properties:
 *           buffer:
 *             type: object
 *             properties:
 *               type:
 *                 type: string
 *               data:
 *                 type: array
 *                 items:
 *                   type: integer
 *                   format: int64
 *           offset:
 *             type: integer
 *             format: int64
 *           markedOffset:
 *             type: integer
 *             format: int64
 *           limit:
 *             type: integer
 *             format: int64
 *           littleEndian:
 *             type: boolean
 *           noAssert:
 *             type: boolean
 *   BlockStat:
 *     properties:
 *       header:
 *         type: object
 *         properties:
 *           number:
 *             type: string
 *           previous_hash:
 *             type: string
 *           data_hash:
 *             type: string
 *       data:
 *         type: object
 *         additionalProperties: {}
 *       metadata:
 *         type: object
 *         additionalProperties: {}
 */

/**
 * @swagger
 * securityDefinitions:
 *   basicAuth:
 *     type: basic
 *     description: HTTP Basic Authentication.
 */

//===========================================
//Login
//===========================================

/**
 * @swagger
 * /common/api/v1/login:
 *   get:
 *     tags:
 *       - Login
 *     description: Returns login token; if basic auth is provided, basic auth will be used instead of id and password parameters
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: user-id
 *         in: header
 *         description: User ID
 *         required: false
 *         type: string
 *         format: string
 *       - name: password
 *         in: header
 *         description: Password
 *         required: false
 *         type: string
 *         format: string
 *       - name: login-org
 *         in: header
 *         description: Certificate Authority (CA) organization
 *         required: false
 *         type: string
 *         format: string
 *       - name: login-channel
 *         in: header
 *         description: Blockchain Channel
 *         required: false
 *         type: string
 *         format: string
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: A response object with token
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/LoginResponse'
 */
router.route('/login').get(function (req, res) {
    let login_info = route_login.getLoginInfo(req);
    let id = login_info["id"];
    let password = login_info["password"];
    let channel = login_info["channel"];
    let org = login_info["org"];

    if (!id) {
        let errmsg = "user id is missing";
        logger.error(errmsg);
        res.status(unauthorizedError).json({ msg: "Invalid data:" + errmsg, status: unauthorizedError });
    } else if (!password) {
        let errmsg = "password is missing";
        logger.error(errmsg);
        res.status(unauthorizedError).json({ msg: "Invalid data:" + errmsg, status: unauthorizedError });
    } else if (!channel) {
        let errmsg = "channel header is missing";
        logger.error(errmsg);
        res.status(unauthorizedError).json({ msg: "Invalid data:" + errmsg, status: unauthorizedError });
    } else if (!org) {
        let errmsg = "ca-org header is missing";
        logger.error(errmsg);
        res.status(unauthorizedError).json({ msg: "Invalid data:" + errmsg, status: unauthorizedError });
    } else {

        let data = {
            type: 'getLoginToken',
            id: id,
            password: password,
            org: org,
            channel: channel
        };
        req_handler.process_api(data, req, res);
    }
});

/**
 * @swagger
 * /common/api/v1/refreshToken:
 *   get:
 *     tags:
 *       - Login
 *     description: "Obtain refresh token to extend session lifetime."
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: Return refresh token
 */
router.route('/refreshToken').get(function (req, res) {
    let login_info = route_login.getLoginInfo(req);
    let id = login_info["id"];
    let password = login_info["password"];
    let channel = login_info["channel"];
    let org = login_info["org"];
    let data = {
        type: 'getRefreshToken',
    };
    req_handler.process_api(data, req, res);

});


/**
 * @swagger
 * /common/api/v1/public_key:
 *   get:
 *     tags:
 *       - Login
 *     description: Returns public key to be used for payload encryption
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: public key to be used for payload encryption
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/LoginResponse'
 */
router.route('/public_key').get(function (req, res) {
    let pubkey = req_handler.solutionConfig["app_admin"]["public_key"];
    if (!hasPemHeader(pubkey)) {
        pubkey = "-----BEGIN PUBLIC KEY-----\n" + pubkey + "\n-----END PUBLIC KEY-----\n";
    }
    res.json({ public_key: pubkey });
});


//===========================================
//Sign
//===========================================

/**
 * @swagger
 * /common/api/v1/sign:
 *   post:
 *     tags:
 *       - Sign
 *     description: "[USE ONLY FOR TESTING PURPOSE] Proxy to sign an API request. Default algorithm is sha256."
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: user-id
 *         in: header
 *         description: User ID
 *         required: false
 *         type: string
 *         format: string
 *       - name: password
 *         in: header
 *         description: Password
 *         required: false
 *         type: string
 *         format: string
 *       - name: login-org
 *         in: header
 *         description: Certificate Authority (CA) organization
 *         required: false
 *         type: string
 *         format: string
 *       - name: login-channel
 *         in: header
 *         description: Blockchain Channel
 *         required: false
 *         type: string
 *         format: string
 *       - name: data
 *         description: Private key and payload
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/SignData'
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: Return object for the API path
 */
router.route('/sign').post(function (req, res) {
    let login_info = route_login.getLoginInfo(req);
    let enrollId = login_info["id"];

    let id = req.body.user_id ? req.body.user_id : enrollId;
    let signKey = req.body.sign_key + '';
    let payload = req.body.payload;
    let algorithm = req.body.algorithm ? req.body.algorithm : 'sha256';
    let api_path = req.body.api_path + '';
    let method = req.body.method + '';

    if (!id) {
        let errmsg = "user id is missing";
        logger.error(errmsg);
        res.status(unauthorizedError).json({ msg: "Invalid data:" + errmsg, status: unauthorizedError });
    } else if (!api_path || api_path == "/") {
        let errmsg = "API path is missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!signKey) {
        let errmsg = "signing key is missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else {
        let payloadJson = null;
        if (payload) {
            if (typeof payload === 'string' || payload instanceof String) {
                try {
                    payloadJson = JSON.parse(payload);
                } catch (err) {
                    let errmsg = "invalid payload";
                    logger.error(errmsg);
                    res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
                    return;
                }
            } else {
                payloadJson = payload;
                payload = JSON.stringify(payloadJson);
            }
        }

        if (!hasPemHeader(signKey)) {
            signKey = "-----BEGIN RSA PRIVATE KEY-----\n" + signKey + "\n-----END RSA PRIVATE KEY-----\n";
        }
        let message = id + api_path;
        if (payload && (method == "POST" || method == "PUT")) {
            message = message + payload;
        }

        const signer = crypto.createSign(algorithm);
        signer.update(message);
        signer.end();
        const signature = signer.sign(signKey);
        const signatureB64 = signature.toString('base64');
        const signString = signatureB64 + ':' + algorithm;
        logger.debug("Signing the request:", signString);

        const url = req.protocol + '://' + req.get('host') + api_path;
        const is_proxy = true === req.body.is_proxy ? true : false;
        const encrypt_payload = true === req.body.encrypt_payload ? true : false;

        //encrypt payload
        if (encrypt_payload && payload) {
            logger.debug("encrypt payload")
            let key = kms.getRandomKey();
            let iv = kms.getRandomIV();
            let encPayload = kms.encryptAesSymKey(key, payload, 'utf8', 'base64', iv, false);
            let keyB64 = key.toString("base64");
            let pubkey = req_handler.solutionConfig["app_admin"]["public_key"];
            let encKeyHex = kms.encryptRSA(keyB64, pubkey);
            let encKeyB64 = Buffer.from(encKeyHex, 'hex').toString('base64');
            let ivB64 = iv.toString('base64');
            payloadJson = {
                _key_: encKeyB64,
                _iv_: ivB64,
                _data_: encPayload
            };
            payload = JSON.stringify(payloadJson);
        }
        let headers = { 'Content-Type': 'application/json' }
        headers["signature"] = signString;
        if (req.headers.authorization) {
            headers['authorization'] = req.headers.authorization;
        }
        if (req.headers.authorization) {
            headers['token'] = req.headers.token;
        }
        if (req.headers['user-id']) {
            headers['user-id'] = req.headers['user-id'];
        }
        if (req.headers['password']) {
            headers['password'] = req.headers['password'];
        }
        if (req.headers['login-org']) {
            headers['login-org'] = req.headers['login-org'];
        }
        if (req.headers['login-channel']) {
            headers['login-channel'] = req.headers['login-channel'];
        }
        if (req.headers['Cookie']) {
            headers['Cookie'] = req.headers['Cookie'];
        }
        if (req.headers['cookie']) {
            headers['cookie'] = req.headers['cookie'];
        }
        if (!is_proxy) {
            let resJson = {
                methond: method,
                url: url,
                headers: headers
            };
            if (payloadJson) {
                resJson["payload_json"] = payloadJson;
                resJson["payload_string"] = payload;
            }
            res.json(resJson);
        } else {
            let options = {
                uri: url,
                method: method,
                headers: headers,
                json: true,
                strictSSL: false
            };
            if (payloadJson) {
                options['body'] = payloadJson;
            }
            request(options, function (err, res2, body) {
                if (err) {
                    let errmsg = err.toString();
                    logger.error(err);
                    res.status(500).json({ msg: "Server error:" + errmsg, status: 500 });
                } else {
                    if (res2.headers["set-cookie"]) {
                        res.header("set-cookie", res2.headers["set-cookie"]);
                    }
                    if (res2.headers["cookie"]) {
                        res.header("cookie", res2.headers["cookie"]);
                    }
                    res.json(body);
                }
            });
        }
    }
});

//check if key already has header or not
function hasPemHeader(key) {
    return key.startsWith("-----BEGIN");
}

//===========================================
//Orgs
//===========================================

/**
 * @swagger
 * /common/api/v1/orgs:
 *   post:
 *     tags:
 *       - Organizations
 *     description: "Register a new org"
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: Org
 *         description: Org Object
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/OrgNew'
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: Org registration response object
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/OrgResponse'
 */
router.route('/orgs').post(function (req, res) {
    const verify_signature = req_handler.solutionConfig["verify_user_signature"];
    if (!req.body.id) {
        let errmsg = "id missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.name) {
        let errmsg = "name missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.email) {
        let errmsg = "email missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.status || req.body.status != "active") {
        let errmsg = "status has to be \"active\"";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.tax_id) {
        let errmsg = "tax_id missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.address) {
        let errmsg = "address missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.role) {
        let errmsg = "role mission";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (verify_signature && !req.body.verify_key) {
        let errmsg = "verify key is missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else {
        let data = {
            type: 'registerOrg',
            id: req.body.id,
            secret: req.body.secret,
            ca_org: req.body.ca_org,
            name: req.body.name,
            role: "org",
            email: req.body.email,
            status: req.body.status,
            is_group: true,
            tax_id: req.body.tax_id,
            address: req.body.address,
            solution_level_role: req.body.role,
            data: req.body.data && typeof req.body.data == 'object' ? req.body.data : {},
            public_key: req.body.public_key ? req.body.public_key + "" : "",
            private_key: req.body.private_key ? req.body.private_key + "" : "",
            sym_key: req.body.sym_key ? req.body.sym_key + "" : "",
            verify_key: req.body.verify_key ? req.body.verify_key + "" : "",
            action: "register"
        };
        req_handler.process_api(data, req, res);
    }
});


/**
 * @swagger
 * /common/api/v1/orgs/{org_id}:
 *   put:
 *     tags:
 *       - Organizations
 *     description: Update an organization
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: org_id
 *         description: Organization id
 *         in: path
 *         required: true
 *         type: string
 *       - name: Org
 *         description: Organization detail
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/OrgUpdate'
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: Successfully updated
 */
router.route('/orgs/:org_id').put(function (req, res) {
    if (!req.body.id) {
        let errmsg = "id missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (req.body.id != req.params.org_id) {
        let errmsg = "ID in path and data body does not match";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: errmsg, status: invalidDataError });
    } else if (!req.body.name) {
        let errmsg = "name missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.status || req.body.status != "active") {
        let errmsg = "status has to be \"active\"";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.tax_id) {
        let errmsg = "tax_id missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.address) {
        let errmsg = "address missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.role) {
        let errmsg = "role missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else {
        let data = {
            type: 'updateOrg',
            id: req.body.id,
            name: req.body.name,
            secret: req.body.secret,
            role: "org",
            ca_org: req.body.ca_org,
            status: req.body.status,
            is_group: true,
            tax_id: req.body.tax_id,
            address: req.body.address,
            solution_level_role: req.body.role,
            data: req.body.data && typeof req.body.data == 'object' ? req.body.data : {}
        };
        req_handler.process_api(data, req, res);
    }
});

/**
 * @swagger
 * /common/api/v1/orgs:
 *   get:
 *     tags:
 *       - Organizations
 *     description: Returns all organizations
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: An array of organization objects
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/Org'
 */
router.route('/orgs').get(function (req, res) {
    let data = {
        type: 'getOrgs'
    };
    req_handler.process_api(data, req, res);
});

/**
 * @swagger
 * /common/api/v1/orgs/{org_id}:
 *   get:
 *     tags:
 *       - Organizations
 *     description: Returns a organization detail
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: org_id
 *         description: Organization name (id)
 *         in: path
 *         required: true
 *         type: string
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: A single organization
 *         schema:
 *           $ref: '#/definitions/Org'
 */
router.route('/orgs/:org_id').get(function (req, res) {
    let data = {
        type: 'getOrg',
        id: req.params.org_id
    };
    req_handler.process_api(data, req, res);
});



//===========================================
//user
//===========================================


/**
 * @swagger
 * /common/api/v1/users:
 *   post:
 *     tags:
 *       - Users
 *     description: "Register a new user<br>Note: Org admin user is registered by Register Org API"
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: User
 *         description: User Object
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/UserNew'
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: User Registration response object with enroll id and secret
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/UserResponse'
 */
router.route('/users').post(function (req, res) {
    const verify_signature = req_handler.solutionConfig["verify_user_signature"];
    let api_admin = req.session["api-admin"];
    if (!req.body.id) {
        let errmsg = "id missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!/^[a-z0-9]+$/i.test(req.body.id)) {
        let errmsg = "id may only contain alphanumeric characters";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.name) {
        let errmsg = "name missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.email) {
        let errmsg = "email missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.role) {
        let errmsg = "role missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (verify_signature && !req.body.verify_key) {
        let errmsg = "verify key is missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else {
        let data = {
            type: 'registerUser',
            id: req.body.id,
            secret: req.body.secret,
            name: req.body.name,
            role: "user",
            ca_org: req.body.ca_org,
            email: req.body.email,
            status: "active",
            is_group: false,
            solution_level_role: req.body.role,
            data: req.body.data && typeof req.body.data == 'object' ? req.body.data : {},
            public_key: req.body.public_key ? req.body.public_key + "" : "",
            private_key: req.body.private_key ? req.body.private_key + "" : "",
            sym_key: req.body.sym_key ? req.body.sym_key + "" : "",
            verify_key: req.body.verify_key ? req.body.verify_key + "" : "",
            action: "register"
        };
        req_handler.process_api(data, req, res);
    }
});


/**
 * @swagger
 * /common/api/v1/orgs/{orgID}/users/{userID}:
 *   post:
 *     tags:
 *       - Users
 *     description: Adds a user to an org either as an admin or as a member
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: orgID
 *         description: Org that userID will be added to
 *         in: path
 *         required: true
 *         type: string
 *       - name: userID
 *         description: User that is being put into orgID
 *         in: path
 *         required: true
 *         type: string
 *       - name: isAdmin
 *         description: Determines whether or not userID will be added to orgID as an admin or as a member
 *         in: query
 *         required: true
 *         default: false
 *         type: boolean
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: Successfully put user in org
 */
router.route('/orgs/:orgID/users/:userID').post(function (req, res) {
    let isAdmin = "false"
    if (req.query.isAdmin === true || req.query.isAdmin === "true") {
        isAdmin = "true"
    }
    if (!req.params.userID) {
        let errmsg = "userID missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid userID: " + errmsg, status: invalidDataError });
    } else if (!req.params.orgID) {
        let errmsg = "orgID missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid orgID: " + errmsg, status: invalidDataError });
    } else {
        let data = {
            type: 'putUserInOrg',
            userID: req.params.userID,
            orgID: req.params.orgID,
            isAdmin: isAdmin
        };
        req_handler.process_api(data, req, res);
    }
});


/**
 * @swagger
 * /common/api/v1/users/{user_id}:
 *   put:
 *     tags:
 *       - Users
 *     description: "Update an user"
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: user_id
 *         description: User id
 *         in: path
 *         required: true
 *         type: string
 *       - name: User
 *         description: User Object
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/UserUpdate'
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: User Registration response object with enroll id and secret
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/UserResponse'
 */
router.route('/users/:user_id').put(function (req, res) {
    if (!req.body.id) {
        let errmsg = "id missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (req.params.user_id != req.body.id) {
        let errmsg = "id mismatch";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid id: " + errmsg, status: invalidDataError });
    } else if (!req.body.name) {
        let errmsg = "name missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.status || (req.body.status != "active" && req.body.status != "inactive")) {
        let errmsg = "status has to be either \"active\" or \"inactive\"";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else if (!req.body.role) {
        let errmsg = "role missing";
        logger.error(errmsg);
        res.status(invalidDataError).json({ msg: "Invalid data:" + errmsg, status: invalidDataError });
    } else {
        let data = {
            type: 'updateUser',
            id: req.body.id,
            name: req.body.name,
            secret: req.body.secret,
            role: "user",
            ca_org: req.body.ca_org,
            status: req.body.status,
            solution_level_role: req.body.role,
            data: req.body.data && typeof req.body.data == 'object' ? req.body.data : {}
        };
        req_handler.process_api(data, req, res);
    }
});



/**
 * @swagger
 * /common/api/v1/users/{user_id}:
 *   get:
 *     tags:
 *       - Users
 *     description: Returns user details
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: user_id
 *         description: User name (id)
 *         in: path
 *         required: true
 *         type: string
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: User Object
 *         schema:
 *           $ref: '#/definitions/User'
 */
router.route('/users/:user_id').get(function (req, res) {
    let data = {
        type: 'getUser',
        userid: req.params.user_id
    };
    req_handler.process_api(data, req, res);
});


/**
 * @swagger
 * /common/api/v1/orgs/{org_id}/users:
 *   get:
 *     tags:
 *       - Users
 *     description: "Returns all users for an organization; You can filter using optional query string role="
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: org_id
 *         description: Organization name (id)
 *         in: path
 *         required: true
 *         type: string
 *       - name: role
 *         description: "role filter (Note: roles include 'user', 'org', 'audit', and 'system')"
 *         in: query
 *         required: false
 *         type: string
 *         default: ""
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: Array of user object
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/User'
 */
router.route('/orgs/:org_id/users').get(function (req, res) {
    let data = {
        type: 'getUsers',
        org: req.params.org_id,
        role: req.query.role || req.query.r || ""
    };
    req_handler.process_api(data, req, res);
});

//===========================================
//chain
//===========================================
/**
 * @swagger
 * /common/api/v1/chain:
 *   get:
 *     tags:
 *       - Chain
 *     description: Returns chain stat
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: ChainStat Object
 *         schema:
 *           $ref: '#/definitions/ChainStat'
 */
router.route('/chain').get(function (req, res) {
    let data = {
        type: 'getChainStat'
    };
    req_handler.process_api(data, req, res);
});

/**
 * @swagger
 * /common/api/v1/chain/blocks/{block_no}:
 *   get:
 *     tags:
 *       - Chain
 *     description: Returns block stat
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: block_no
 *         description: Block number
 *         in: path
 *         required: true
 *         type: integer
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: BlockStat Object
 *         schema:
 *           $ref: '#/definitions/BlockStat'
 */
router.route('/chain/blocks/:block_no').get(function (req, res) {
    let data = {
        type: 'getBlockStat',
        block_no: req.params.block_no
    };
    req_handler.process_api(data, req, res);
});

//===========================================
// MFA
//===========================================
/**
 * @swagger
 * /common/api/v1/mfa/{authCode}:
 *   get:
 *     tags:
 *       - MFA
 *     description: get user details using authCode
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: authCode
 *         description: auth code returned from MFA
 *         in: path
 *         required: true
 *         type: string
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: A user detail
 */
router.route('/mfa/:authCode').get(function (req, res) {
    let data = {
        type: 'getLoginTokenByAuthCode',
        authCode: req.params.authCode
    };
    req_handler.process_api(data, req, res);
});

/**
 * @swagger
 * /common/api/v1/networkconfig/:
 *   put:
 *     tags:
 *       - Network Connection Profile
 *     description: Merge Network Connection Profile
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         description: login token
 *         required: false
 *         type: string
 *         format: string
 *       - name: signature
 *         in: header
 *         description: user signature
 *         required: false
 *         type: string
 *         format: string
 *       - name: Network Connection Profile
 *         description: Network Connection Profile
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/NetworkConfig'
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: Return object for the API path
 */
router.route('/networkconfig').put(function (req, res) {
    let data = {
        type: 'mergeNetworkConfig',
        networkConfig: req.body.networkConfig
    };
    req_handler.process_api(data, req, res);
});

module.exports = { common_api_base: common_api_base, router: router };
