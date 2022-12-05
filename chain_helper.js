/*******************************************************************************
 *
 *
 * (c) Copyright Merative US L.P. and others 2020-2022 
 *
 * SPDX-Licence-Identifier: Apache 2.0
 *
 *******************************************************************************/
'use strict';

var TAG = 'chain_helper.js';

var user_manager = require('../utils/user_manager.js');
var kms = require('../utils/kms.js');
var hfc = require('fabric-client');
var log4js = require('log4js');
var logger = log4js.getLogger(TAG);
var log_level = hfc.getConfigSetting('log_level') ? hfc.getConfigSetting('log_level') : "INFO";
logger.level = log_level;

const { getData, setData } = require('../utils/cache/redisService');
const {parse, stringify} = require('flatted');
 
var path = require('path');
var util = require('util');
var fs = require('fs-extra');
var caService = require('fabric-ca-client');
var md5Dir = require('md5-dir');
const x509 = require('@ampretia/x509');
var yaml = require('js-yaml');
var ip = require('ip');

const loadbalance = require('loadbalance');

//Config keys. Todo Add other keys
const ConfigKeys = {
    fabric_version: "hyperledger_fabric_version"
}

//Config values
const SolutionConfigValues = {
    fabric11_IBP1_version: "1.1-ibp",
    fabric14_IBP1_version: "1.4-ibp",
    fabric11_Dev_Version: "1.1",
    fabric14_Dev_Version: "1.4"
}

hfc.setLogger(logger);

var defaultNetworkConfig;
var defaultSolutionConfig;
var defaultChannelConfigs = {};
var chainSetupDone = false;

module.exports.setup = function () {
    logger.info('Chain setup initialization');

    // setup GOPATH
    process.env.GOPATH = path.join(__dirname, "../..", hfc.getConfigSetting('chaincode_src_path'), "../");
    logger.info("GOPATH=" + process.env.GOPATH);

    //initCredentialStore
    if (hfc.getConfigSetting("key_value_store_module")) {
        let key_val_store = hfc.getConfigSetting("key_value_store_module");
        if (key_val_store.startsWith(".")) {
            hfc.setConfigSetting("key-value-store", path.resolve(path.join(__dirname, "../..", key_val_store)));
        } else {
            hfc.setConfigSetting("key-value-store", key_val_store);
        }
    }
    logger.info("key-value-store=", hfc.getConfigSetting("key-value-store"));

    // load default network config
    const file_path = path.resolve(path.join(__dirname, '../..', hfc.getConfigSetting('network_config_file')));
    const file_data = fs.readFileSync(file_path);
    const file_ext = path.extname(file_path);
    // maybe the file is yaml else has to be JSON
    if(file_ext.indexOf('y') > -1) {
        defaultNetworkConfig = yaml.safeLoad(file_data);
    } else {
        defaultNetworkConfig = JSON.parse(file_data);
    }
    logger.info("Network config loaded successfully");

    // load default solution config
    const file_path2 = path.resolve(path.join(__dirname, '../..', hfc.getConfigSetting('solution_config_file')));
    let file_data2 = fs.readFileSync(file_path2).toString().replace(/\$\{HOST_IP\}/g,ip.address());
    file_data2 = file_data2.replace(/\$\{CLOUDANT_USERNAME\}/g, process.env.CLOUDANT_USERNAME);
    file_data2 = file_data2.replace(/\$\{CLOUDANT_PASSWORD\}/g, process.env.CLOUDANT_PASSWORD);
    file_data2 = file_data2.replace(/\$\{CLOUDANT_DATABASE\}/g, process.env.CLOUDANT_DATABASE);
    file_data2 = file_data2.replace(/\$\{CLOUDANT_HOST\}/g, process.env.CLOUDANT_HOST);
    file_data2 = file_data2.replace(/\$\{HOST_IP\}/g, ip.address());
    const file_ext2 = path.extname(file_path2);
    // maybe the file is yaml else has to be JSON
    if(file_ext2.indexOf('y') > -1) {
        defaultSolutionConfig = yaml.safeLoad(file_data2);
    } else {
        defaultSolutionConfig = JSON.parse(file_data2);
    }

    for (let solutionName in defaultSolutionConfig["solutions"]) {
        for (let channelName in defaultSolutionConfig["solutions"][solutionName]["channels"]) {
            defaultChannelConfigs[channelName] = defaultSolutionConfig["solutions"][solutionName]["channels"][channelName];
        }
    }

    logger.info("Solution config loaded successfully");

    logger.info('Chain setup initialized successfully');
}


exports.solutionConfig = function () { return defaultSolutionConfig; };
exports.networkConfig = function () { return defaultNetworkConfig; };
exports.channelConfigs = function () { return defaultChannelConfigs; };

var sleep = async function (sleep_time_ms) {
    return new Promise(resolve => setTimeout(resolve, sleep_time_ms));
}


//setupChain
//cb(error, clients, channels, caClients, adminUser, appAdminUser, appAdminKeyId);
exports.setupChain = setupChain;
async function setupChain() {
    logger.info("===========================================");
    logger.info("====         Start Chain Setup         ====");
    try {

        logger.info("====       Start Enroll Admin Users for Orgs");
        await enrollAdminUsers();

        logger.info("====       Start Initialize Channels");
        await initializeChannels();

        logger.info("====       Start Deploy Solutions");
        await deploySolutions();

        logger.info("====          Chain Setup Done         ====");
        logger.info("===========================================\n\n");
        chainSetupDone = true;

        return chainSetupDone;

    } catch (err) {
        logger.error(err);
        logger.error("====         Chain Setup failed        ====");
        logger.error("===========================================\n\n");
        chainSetupDone = false;
        throw err;
    }
}


// get admin registar info from default network configuration
exports.getAminUserInfoForOrg = getAminUserInfoForOrg;
function getAminUserInfoForOrg(orgName) {
    let orgs= defaultNetworkConfig["organizations"];
    let org = orgs && orgs[orgName] ? orgs[orgName] : null;
    let caName = org && org['certificateAuthorities'] ? org['certificateAuthorities'][0] : null;
    let cas = defaultNetworkConfig['certificateAuthorities'];
    let ca = cas && cas[caName] ? cas[caName] : null;
    let adminInfo = ca && ca['registrar']? ca['registrar'] : [];
    return adminInfo;
}

function getMspidOfOrg(orgName) {
    let orgs= defaultNetworkConfig["organizations"];
    let org = orgs && orgs[orgName] ? orgs[orgName] : null;
    if (org) {
        return org["mspid"];
    } else {
        return null;
    }
}

// create client instance for the org
// if username and secret is provided, try to enroll the user, and set the context
// if only username is provided, try to get user from persistance
exports.getClientForOrg = getClientForOrg;
async function getClientForOrg (userorg, username, usersecret) {
    logger.debug('getClientForOrg - ****** START %s %s', userorg, username)
    // get a fabric client loaded with a connection profile for this org
    // build a client context and load it with a connection profile
    // lets only load the network settings and save the client for later
    let client = new hfc(); 
    client.loadFromConfig(defaultNetworkConfig);

    // Dynamically generate client config
    const clientConfig = {
        description: "client config for " + userorg,
        version: "1.0",
        client: {
            organization: userorg,
            credentialStore: {
                path: path.resolve(path.join(__dirname, '../../tmp',  'fabric-client-kv-'+userorg)),
                cryptoStore: {
                    path: path.resolve(path.join(__dirname, '../../tmp',  'fabric-client-kv-'+userorg)),
                },
                wallet: null,
            }
        }
    };

    // This will load a connection profile over the top of the current one one
    // since the first one did not have a client section and the following one does
    // nothing will actually be replaced.
    // This will also set an admin identity because the organization defined in the
    // client section has one defined
    client.loadFromConfig(clientConfig);

    // this will create both the state store and the crypto store based
    // on the settings in the client section of the connection profile
    await client.initCredentialStores();

    // Trying to find user from persistance or enroll and set context
    if (username) {
        let user = await client.getUserContext(username, true);
        if(!user) {
            logger.debug('User was not found in persistence:', username);
            if(username && usersecret) {
                let orgs= defaultNetworkConfig["organizations"];
                let org = orgs && orgs[userorg] ? orgs[userorg] : null;
                let caName = org && org['certificateAuthorities'] ? org['certificateAuthorities'][0] : null;
                user = await client.setUserContext({username:username, password:usersecret, caName:caName});
                if(user) {
                    logger.debug('User %s was found and enrolled', username);
                }
            }
        } else {
            logger.debug('User %s was found to be registered and enrolled', username);
        }
        if(!user) {
            throw new Error(util.format('User was not found :', username));
        }
    }
    
    logger.debug('getClientForOrg - ****** END %s %s \n\n', userorg, username)

    return client;
}

exports.getCaClientForOrg = getCaClientForOrg;
async function getCaClientForOrg (userorg) {
    let orgs= defaultNetworkConfig["organizations"];
    let org = orgs && orgs[userorg] ? orgs[userorg] : null;
    let caId = org && org['certificateAuthorities'] ? org['certificateAuthorities'][0] : null;
    let cas = defaultNetworkConfig['certificateAuthorities'];
    let ca = cas && cas[caId] ? cas[caId] : null;
    let caName = ca && ca['caName'] ? ca['caName'] : "";
    let tlscert = ca && ca['tlsCACerts'] && ca['tlsCACerts']['pem'] ? ca['tlsCACerts']['pem'] : null;
    let caurl = ca && ca['url'] ? ca['url'] : "";
    let httpVerify = ca && ca['httpOptions'] && ca['httpOptions']['verify'] ? ca['httpOptions']['verify'] === "true" || ca['httpOptions']['verify'] === true : false;
    
    let store_path=path.resolve(path.join(__dirname, '../../tmp',  'fabric-client-kv-'+userorg))
    let crypto_suite = hfc.newCryptoSuite();
    let crypto_store = hfc.newCryptoKeyStore({path: store_path});
    crypto_suite.setCryptoKeyStore(crypto_store);
    let tlsOptions = {
            trustedRoots: [tlscert],
            verify: httpVerify
        };
    
    logger.debug("geting caClient:", userorg, tlsOptions, caName);
    // be sure to change the http to https when the CA is running TLS enabled
    let fabric_ca_client = new caService(caurl, tlsOptions , caName, crypto_suite);
    
    return fabric_ca_client;
}

exports.mergeNetworkConfig = mergeNetworkConfig;
async function mergeNetworkConfig (networkconfig) {
    const organizations = Object.assign({}, defaultNetworkConfig.organizations, networkconfig.organizations);
    const peers = Object.assign({}, defaultNetworkConfig.peers, networkconfig.peers);
    const certificateAuthorities = Object.assign({}, defaultNetworkConfig.certificateAuthorities, networkconfig.certificateAuthorities);
    for(let channel of Object.keys(networkconfig.channels)) {
        if (Object.keys(defaultNetworkConfig.channels).includes(channel)) {
            const xMembers1 = defaultNetworkConfig.channels[channel]['x-members'] || [];
            //logger.debug("Channel: %s     xMembers: %s", channel, xMembers1);
            const xMembers2 = networkconfig.channels[channel]['x-members'] || [];
            //logger.debug("Channel: %s     xMembers: %s", channel, xMembers2);
            const mergedXMembers = xMembers1.concat(xMembers2.filter(item => !xMembers1.includes(item)));
            //logger.debug("Channel: %s     mergedXMembers: %s", channel, mergedXMembers);
            defaultNetworkConfig.channels[channel]['x-members'] = mergedXMembers;
        }
    }
    defaultNetworkConfig.organizations = organizations;
    defaultNetworkConfig.peers = peers;
    defaultNetworkConfig.certificateAuthorities = certificateAuthorities;
    //logger.debug('mergeNetworkConfig - ****** END %s \n\n', JSON.stringify(defaultNetworkConfig))
    
    logger.info("NetworkConfig organization merged: ", Object.keys(organizations));
    logger.info("NetworkConfig peers merged: ", Object.keys(peers));
    logger.info("NetworkConfig CA merged: ", Object.keys(certificateAuthorities));
    return defaultNetworkConfig;
}


exports.getAdminClientForOrg = getAdminClientForOrg;
async function getAdminClientForOrg (orgName) {
    let adminInfo = getAminUserInfoForOrg(orgName);
    if (!adminInfo || adminInfo.length == 0) {
        throw new Error("Unable to find admin user for " + orgName);
    }
    const adminEnrollId = adminInfo[0].enrollId;
    const adminEnrollSecret = adminInfo[0].enrollSecret;

    let client = await getClientForOrg(orgName, adminEnrollId, adminEnrollSecret);
    return client;
}


exports.registerUser = registerUser;
async function registerUser (caClient, admin, username, usersecret, userrole, userorg, affiliation, attrs) {
    if (hfc.getConfigSetting(ConfigKeys.fabric_version) === SolutionConfigValues.fabric14_IBP1_version && affiliation) {
        //We don't configure affiliation by default in IBP2 CA, but if a solution passes in affiliation, honor it.
        logger.info('Using affiliation during CA register: ');
    }
    //using IBP1.x : affliation looks like ibp.PeerOrg1         
    else if(hfc.getConfigSetting(ConfigKeys.fabric_version) === SolutionConfigValues.fabric11_IBP1_version) {
        if (!affiliation)
            affiliation = "ibp."+userorg;    
    }
        
    /* Removing pre HL 1.1 conditionals
    else if (hfc.getConfigSetting(ConfigKeys.fabric_version) === (SolutionConfigValues.fabric14_Dev_version)) {  //TODO test affliation format using IBP2.x
            affiliation = userorg.toLowerCase()+".department1";
    }
        else {
        affiliation = userorg.toLowerCase();
    }
    */
    
    let registerRequest = {
        enrollmentID: username,
        enrollmentSecret: usersecret,        
        role: userrole,
        maxEnrollments: -1,
        attrs: attrs
    }

    if (affiliation) {
        registerRequest["affiliation"] = affiliation;
        logger.info('Using affiliation in CA register: ', affiliation);
    }

    let secret = await caClient.register( registerRequest, admin);
    logger.info("Successfully registered user:", username);
    return secret;
}

// enroll user
// if client is passed, also set user context
exports.enrollUser = enrollUser;
async function enrollUser(username, userSecret, userOrg, attr_reqs, client) {
    try {
        // attempt to get from cache first
        let cacheKey = username + "_enrollment";
        let userEnrollment = await getData(cacheKey);

        let cacheKeySecret = username + "_secret";
        let cachedUserSecret = await getData(cacheKeySecret);

        if (!userEnrollment) {
            let caClient = await getCaClientForOrg(userOrg);

            // enroll user
            let req = {enrollmentID: username, enrollmentSecret: userSecret, profile: "tls"};
            if (attr_reqs) {
                req["attr_reqs"] = attr_reqs
            }
            let enrollment = await caClient.enroll(req);
            logger.info('Successfully enrolled user ' + username);
            if (client) {
                let orgs= defaultNetworkConfig["organizations"];
                let org = orgs && orgs[userOrg] ? orgs[userOrg] : null;
                let caName = org && org['certificateAuthorities'] ? org['certificateAuthorities'][0] : null;
                let user = await client.setUserContext({username:username, password:userSecret, caName:caName});
                if (user) {
                    logger.debug('Successfully got the user context ' + username);
                }
            }

            // update cache
            await setData(cacheKey, stringify(enrollment));
            await setData(cacheKeySecret, req["enrollmentSecret"]);
            return enrollment;
        } else if (cachedUserSecret === userSecret) {
            logger.debug("Retrieved user enrollment from cache for user: ", username);
            return parse(userEnrollment);
        } else {
            const err = new Error('userSecret is not valid for ' + username);
            logger.error('Failed to enroll user: %s with error: %s', username, err.toString());
            throw err;
        }
    } catch(error) {
        logger.error('Failed to enroll user: %s with error: %s', username, error.toString());
        throw new Error('Failed to enroll user ' + username);
    }
}

// return registerd user
// if user is not enrolled, try to enroll
// and set contex of client with the user
// return null if user is not registered
exports.getRegisteredUser = getRegisteredUser;
async function getRegisteredUser(username, userSecret, userOrg, client) {
    try {
        var user = null;
        if (!client) {
            client = await getClientForOrg(userOrg, username, userSecret);
            user = await client.getUserContext(username, true);
            logger.debug('Successfully loaded registered user '+ username);
        } else {
            user = await client.getUserContext(username, true);
            if(!user) {
                if(username && userSecret) {
                    let orgs= defaultNetworkConfig["organizations"];
                    let org = orgs && orgs[userOrg] ? orgs[userOrg] : null;
                    let caName = org && org['certificateAuthorities'] ? org['certificateAuthorities'][0] : null;
                    user = await client.setUserContext({username:username, password:userSecret, caName:caName});
                    if(user) {
                        logger.debug('Successfully got registered user ' + username);
                    }
                }
            } else {
                logger.debug('Successfully loaded registered user '+ username);
            }
        }
        if(!user) {
            throw new Error('Failed to get user '+ username);
        }
        return user;
    } catch(error) {
        logger.error('Failed to get registered user: %s with error: %s', username, error.toString());
        throw new Error('Failed to get user '+ username);
    }
}

async function enrollAdminUsers() {
    if(defaultNetworkConfig && defaultNetworkConfig["organizations"]) {
        for(let orgName in defaultNetworkConfig["organizations"]) {
            try {
                await enrollAdminUserForOrg(orgName);
                logger.info("Successfully enrolled admin user for "+orgName);
            } catch (err) {
                logger.error(err);
                logger.error("Failed to enroll admin user for "+orgName);
                throw new Error("Failed to enroll admin user for "+orgName);
            }
        }
    }
    return true;
}

//enroll admin user and set user context
async function enrollAdminUserForOrg(orgName) {
    let adminInfo = getAminUserInfoForOrg(orgName);
    if (!adminInfo || adminInfo.length === 0) {
        throw new Error("Unable to find admin user for " + orgName);
    }
    const adminEnrollId = adminInfo[0].enrollId;
    const adminEnrollSecret = adminInfo[0].enrollSecret;
    let enrollment;
    try {
        enrollment = await enrollUser(adminEnrollId, adminEnrollSecret, orgName);
    } catch (err) {
        logger.error("admin user enrollment failed: for",orgName, adminEnrollId);
        logger.error(err);
    }
    logger.info("Successfully enrolled admin user for", orgName, adminEnrollId);
    return enrollment;
}


async function initializeChannels() {
    let waittime = parseInt(hfc.getConfigSetting('channel_creation_wait_time'));

    if(defaultNetworkConfig && defaultNetworkConfig["channels"]) {
        for (let channelName in defaultChannelConfigs) {

            let isChannelInNetwork = channelName in defaultNetworkConfig["channels"];
            if (!isChannelInNetwork) {
                throw new Error(util.format("Channel [%s] not found", channelName));
            }

            let orgsToJoin = getOrgsToJoinChannel(channelName);
            //let configPath = getChannelConfigPath(channelName);
            let channelConfig = defaultChannelConfigs[channelName]
            let configPath = path.resolve(path.join(__dirname, '../..', channelConfig["config_path"]));
            let isCreateChannel = ("create_channel" in channelConfig) ? channelConfig["create_channel"] : false;

            for (let i in orgsToJoin) {
                let orgName = orgsToJoin[i];
                try {
                    logger.debug("initialize channel " + channelName +" for " + orgName);
                    let peers = getPeersToJoinChannelForOrg(channelName, orgName);
                    logger.debug("peers to join: ", peers);
                    if (peers.length == 0) {
                        // no peers to join from this org
                        continue;
                    }

                    // first setup the client for this org with admin user
                    let adminInfo = getAminUserInfoForOrg(orgName);
                    var client = await getClientForOrg(orgName,adminInfo[0].enrollId, adminInfo[0].enrollSecret);

                    let peersToJoin = await getPeersNeedToJoinChannel(channelName, orgName, peers, client);
                    logger.debug("peers need to join: ", peersToJoin);

                    if (peersToJoin.length > 0) {
                        if (isCreateChannel) {
                            await createChannel(channelName, configPath, orgName, client);
                            await sleep(waittime); //wait 5 sec for channel creation
                        }
                        await joinChannel(channelName, peersToJoin, orgName, client);
                    }

                    logger.info("Successfully initialized channel "+channelName + " for "+orgName);
                } catch (err) {
                    logger.error(err);
                    logger.error("Failed to initialize channel "+channelName + " for "+orgName);
                    throw new Error("Failed to initialize channel "+channelName + " for "+orgName);
                }
            };


        }
    }
}

// assumes channelName is in the network configuration
function getOrgsToJoinChannel(channelName) {
    //peers in channel config
    let peers = [];
    for (let peerName in defaultNetworkConfig["channels"][channelName]["peers"]) {
        peers.push(peerName);
    }

    //go over each orgs in organization config and check if the peers are in the above list
    let orgNames = [];
    for(let orgName in defaultNetworkConfig["organizations"]) {
        let orgPeers = defaultNetworkConfig["organizations"][orgName]["peers"];
        for (let i in orgPeers) {
            if (peers.includes(orgPeers[i])) {
                orgNames.push(orgName);
                break;
            }
        }
    }

    //logger.debug("orgs to join channel "+ channelName, orgNames);
    return orgNames;
}

//check if org belongs to channel or not
module.exports.isOrgInChannel = isOrgInChannel;
function isOrgInChannel(channelName, orgName) {
    //first try x-members in channel config
    let orgs = [];
    if (defaultNetworkConfig["channels"][channelName]) {
        let members = defaultNetworkConfig["channels"][channelName]["x-members"];
        if (members && members.includes(orgName)) {
            return true
        }
    }

    //call getPeersToJoin/channel ForOrg function
    let peers = getPeersToJoinChannelForOrg(channelName, orgName);
    if (peers.length > 0) {
        return true;
    } else {
        return false;
    }
}

function getPeersToJoinChannelForOrg(channelName, orgName) {
    //peers in channel config
    let peers = [];
    let peerNames = [];
    if (defaultNetworkConfig["channels"][channelName]) {
        for (let peerName in defaultNetworkConfig["channels"][channelName]["peers"]) {
            peers.push(peerName);
        }
    }
    if (peers.length> 0) {
        //go over each orgs in organization config and check if the peers
        //are in the above list, and add it to the orgPeers list

        if (defaultNetworkConfig["organizations"][orgName]) {
            let orgPeers = defaultNetworkConfig["organizations"][orgName]["peers"];
            for (let i in orgPeers) {
                if (peers.includes(orgPeers[i])) {
                    peerNames.push(orgPeers[i]);
                }
            }
        }
    }
    //logger.debug("all peers of org "+ orgName +" for channel "+ channelName +":", peerNames);

    return peerNames;
}


async function getPeersNeedToJoinChannel(channelName, orgName, peers, client) {
    let peerList = [];
    for (let i in peers) {
        let peerName = peers[i];
        let response = await client.queryChannels(peerName, true);
        let channelList = [];
        for (let j in response.channels) {
            channelList.push(response.channels[j].channel_id);
        }
        if (!channelList.includes(channelName)) {
            peerList.push(peerName);
        }
    }
    //logger.debug("all peers of org " + orgName +" need to join channel "+ channelName + " :", peerList);
    return peerList;
}

async function createChannel(channelName, channelConfigPath, orgName, client) {
    logger.debug('Creating Channel \'' + channelName + ' for ' + orgName +  '\'');

    try {
        // read in the envelope for the channel config raw bytes
        var envelope = fs.readFileSync(channelConfigPath);
        // extract the channel config bytes from the envelope to be signed
        var channelConfig = client.extractChannelConfig(envelope);

        //Acting as a client in the given organization provided with "orgName" param
        // sign the channel config bytes as "endorsement", this is required by
        // the orderer's channel creation policy
        // this will use the admin identity assigned to the client when the connection profile was loaded
        let signature = client.signChannelConfig(channelConfig);

        let request = {
            config: channelConfig,
            signatures: [signature],
            name: channelName,
            txId: client.newTransactionID(true) // get an admin based transactionID
        };

        // send to orderer
        var response = await client.createChannel(request)
        //logger.debug('createChannel response ::%j', response);

        if (response && response.status === 'SUCCESS') {
            logger.info('Successfully created channel \'' + channelName + ' for ' + orgName +  '\'');
            return response;
        } else {
            logger.error('Failed to create channel \'' + channelName + ' for ' + orgName +  '\'');
            return response;
        }
    } catch (err) {
        logger.error('Failed to initialize channel \'' + channelName + ' for ' + orgName +  '\'');
        logger.error(err);
        throw new Error('Failed to initialize the channel: ' + err.toString());
    }
}

async function joinChannel(channel_name, peers, org_name, client) {
    var error_message = null;
    var all_eventhubs = [];
    try {
        logger.debug('Calling peers in organization "%s" to join the channel', org_name);

        var channel = client.getChannel(channel_name);
        if(!channel) {
            let message = util.format('Channel %s was not defined in the connection profile', channel_name);
            logger.error(message);
            throw new Error(message);
        }

        // next step is to get the genesis_block from the orderer,
        // the starting point for the channel that we want to join
        let request = {
            txId :  client.newTransactionID(true) //get an admin based transactionID
        };
        let genesis_block = await channel.getGenesisBlock(request);
        
        // tell each peer to join and wait 10 seconds
        // for the channel to be created on each peer
        var promises = [];
        promises.push(new Promise(resolve => setTimeout(resolve, 10000)));
        
        let join_request = {
            targets: peers, //using the peer names which only is allowed when a connection profile is loaded
            txId: client.newTransactionID(true), //get an admin based transactionID
            block: genesis_block
        };
        let join_promise = channel.joinChannel(join_request);
        promises.push(join_promise);
        let results = await Promise.all(promises);
        //logger.debug(util.format('Join Channel R E S P O N S E : %j', results));

        // lets check the results of sending to the peers which is
        // last in the results array
        let peers_results = results.pop();
        // then each peer results
        for(let i in peers_results) {
            let peer_result = peers_results[i];
            if (peer_result instanceof Error) {
                error_message = util.format('Failed to join peer to the channel with error :: %s', peer_result.toString());
                logger.error(error_message);
            } else if(peer_result.response && peer_result.response.status == 200) {
                logger.info('Successfully joined peer to the channel %s',channel_name);
            } else {
                error_message = util.format('Failed to join peer to the channel %s',channel_name);
                logger.error(error_message);
            }
        }
    } catch(error) {
        logger.error('Failed to join channel due to error: ' +  error);
        error_message = error.toString();
    }

    // need to shutdown open event streams
    all_eventhubs.forEach((eh) => {
        eh.disconnect();
    });

    if (!error_message) {
        let message = util.format(
            'Successfully joined peers in organization %s to the channel:%s',
            org_name, channel_name);
        logger.info(message);
        // build a response to send back to the REST caller
        let response = {
            success: true,
            message: message
        };
        return response;
    } else {
        let message = util.format('Failed to join all peers to channel. cause: %s',error_message);
        logger.error(message);
        throw new Error(message);
    }
};


async function deploySolutions() {
    let waittime = parseInt(hfc.getConfigSetting('chaincode_upate_wait_time'));
    for (let solutionName in defaultSolutionConfig["solutions"]) {
        logger.info("Deploying Solution: "+solutionName);
        let solutionConfig = defaultSolutionConfig["solutions"][solutionName];
        
        // register app admin
        let attributeList = await registerAppAdmin(solutionName);

        // install/instantiate/update chaincode
        let instantiated = await installChaincode(solutionName);
        if (instantiated) {
            logger.debug("Wait %d sec in order for chaincode instantiation to be completed", waittime/1000);
            await sleep(waittime);
        }

        // invoke init()
        await invokeInit(solutionName, attributeList);
    }
    return true;
}


async function registerAppAdmin(solutionName) {
    let adminConfig = defaultSolutionConfig["solutions"][solutionName]["app_admin"];

    let orgName = adminConfig["org"];
    let username = adminConfig["username"];
    let email = adminConfig["email"];
    let secret = adminConfig["secret"];
    let pubKey = adminConfig["public_key"];

    var user = {};
    var attr = {};
    try {
        attr = await user_manager.registerUser(username, secret, "system", orgName, email, pubKey);
        logger.info("App admin user for solution "+solutionName +" is registered successfully.");

        return attr;
    } catch (err) {
        logger.error("Failed to register an app admin user ", err);
        throw new Error("Failed to register an app admin user: "+err)
    }
}

//this is the main function to install chaincodes, instantiate or update chaincodes
//if needed
//returns true is chaincode is instantiated
async function installChaincode(solutionName) {
    logger.debug('installChaincode for solution: '+solutionName);
    let solutionConfig = defaultSolutionConfig["solutions"][solutionName]
    let channelConfig = solutionConfig["channels"];
    let chaincodeName = solutionConfig["chaincode"]["name"];
    let chaincodeType = solutionConfig["chaincode"]["type"];
    let chaincodePath = solutionConfig["chaincode"]["path"];
    let init_func = solutionConfig["chaincode"]["init_function"];
    let init_args = solutionConfig["chaincode"]["init_args"];
    let append_hash = solutionConfig["chaincode"]["append_hash_to_version"] ? solutionConfig["chaincode"]["append_hash_to_version"] : null; 
    let endorsement_policy = solutionConfig["chaincode"]["endorsement_policy"];

    let chaincodeVersion = solutionConfig["chaincode"]["version"];
    
    let isInstantiated = false;

    for (let channelName in channelConfig) {
        let orgNames = getOrgsToJoinChannel(channelName);
        let install_chaincode = ("install_chaincode" in channelConfig[channelName]) ? channelConfig[channelName]["install_chaincode"] : false;
        let instantiate_chaincode = ("instantiate_chaincode" in channelConfig[channelName]) ? channelConfig[channelName]["instantiate_chaincode"] : false;
        if (!install_chaincode && !instantiate_chaincode) {
            //isInstantiated = true;
            continue;
        }
        
        let chaincodeDirPath = path.join(__dirname, "../..", hfc.getConfigSetting('chaincode_deploy_path'), chaincodePath);
        if (append_hash) {
            const cchash = md5Dir.sync(chaincodeDirPath);
            chaincodeVersion = chaincodeVersion +"."+cchash;
        }
        
        if (install_chaincode) {
            var client = null;
            for (let i in orgNames) {
                let orgName = orgNames[i];
                var client = await getAdminClientForOrg(orgName);
                let peers = getPeersToInstallChaincodeForOrg(channelName, orgName);
    
                // ********* install chaincode
                //check installed chaincode on each peer and install if needed
                let peerList = [];
                logger.info("Check installed chaincodes for the following peers for org "+orgName+":", peers);
                for (let j in peers) {
                    let peer = peers[j];
                    let installed = false;
                    let chaincodeResponse = await client.queryInstalledChaincodes(peer, true);
                    if (chaincodeResponse) {
                        let chaincodeList = chaincodeResponse.chaincodes;
                        //check if chaincode is already installed
                        for (let i = 0; i < chaincodeList.length; i++) {
                            if (chaincodeList[i].name === chaincodeName &&
                                chaincodeList[i].version === chaincodeVersion) {
                                installed = true;
                                logger.debug("Chaincode is already install on "+peer+":", chaincodeName+"."+chaincodeVersion);
                                break;
                            }
                        }
                    }
                    if (!installed) {
                        peerList.push(peer)
                    }
                }
    
                logger.info("Install chaincode "+ chaincodeName+"."+chaincodeVersion +" for the following peers for org "+orgName+":", peerList);
                // install chaincode for peers that does not have the chaincode
                if (peerList.length > 0 && install_chaincode) {
                    let response = await installChaincodeForOrg(peerList, chaincodeName, chaincodePath, chaincodeVersion, chaincodeType, orgName, client);
                    logger.info(response);
                }
            }
        }


        // TODO - we don't need instantiate for every orgs since instantiate
        // is channel based operation -- for now let's leave it since the second
        // attemp will be skipped anyway
        if (instantiate_chaincode) {
            for (let i in orgNames) {
                let orgName = orgNames[i];
    
                //get first org and first peer of the org
                var client = await getAdminClientForOrg(orgName);
                let peers = getPeersToInstallChaincodeForOrg(channelName, orgName);
                // instantiaate or update chaincode on channel
                // check instantiated chaincode and instantiate or update if needed
                var needInstantiate = "instantiate";
                logger.info("Check instantiated chaincodes for the channel %s for org %s", channelName, orgName);
                var channel = client.getChannel(channelName);
                if(!channel) {
                    let message = util.format('Channel %s was not defined in the connection profile', channelName);
                    logger.error(message);
                    throw new Error(message);
                }
                let instantiateResponse = await channel.queryInstantiatedChaincodes(peers[0], true); //use the admin identity
    
                if (instantiateResponse) {
                    let chaincodeList = instantiateResponse.chaincodes;
                    //check if chaincode is already instantiated
                    for (let i = 0; i < chaincodeList.length; i++) {
                        if (chaincodeList[i].name === chaincodeName &&
                            chaincodeList[i].version ===chaincodeVersion) {
                            needInstantiate = "none";
                            logger.debug("Chaincode is already instantiated on "+channelName+":", chaincodeName+"."+chaincodeVersion);
                            break;
                        } else if (chaincodeList[i].name === chaincodeName) {
                            needInstantiate = "update";
                            logger.debug("Different version of chaincode is already instantiated on "+channelName+":", chaincodeName+"."+chaincodeVersion);
                        }
                    }
                }
    
                logger.debug("Need instantiate or update:", needInstantiate);
                if (needInstantiate != "none" && instantiate_chaincode) {
                    let response = await instantiateChaincode(needInstantiate, peers, channelName, chaincodeName, chaincodeVersion, init_func, chaincodeType, init_args, endorsement_policy, orgNames[0], client);
                    logger.info(response);
                    isInstantiated = true;
                } else {
                    logger.debug("Chaincode %s.%s instantiation is not needed for channel %s %s", chaincodeName, chaincodeVersion, channelName, orgName);
                }
            }
        }

    }

    return isInstantiated;
}

//return endorsing peers and chaincode query peers for the channel
function getPeersToInstallChaincodeForChannel(channelName) {
    //peers in channel config
    let peers = [];
    if (defaultNetworkConfig["channels"][channelName]) {
        for (let peerName in defaultNetworkConfig["channels"][channelName]["peers"]) {
            let peer = defaultNetworkConfig["channels"][channelName]["peers"][peerName];
            if (false !== peer["endorsingPeer"] || false !== peer["chaincodeQuery"]) {
                peers.push(peerName);
            }
        }
    }
    logger.debug("all peers for channel "+ channelName +" need to have the chaincode:", peers);

    return peers;
}

//return non endorsing chaincode query peers for the channel
function getNonEndorsingQueryPeersForChannel(channelName) {
  //peers in channel config
  let peers = [];
  if (defaultNetworkConfig["channels"][channelName]) {
      for (let peerName in defaultNetworkConfig["channels"][channelName]["peers"]) {
          let peer = defaultNetworkConfig["channels"][channelName]["peers"][peerName];
          if (false === peer["endorsingPeer"] && false !== peer["chaincodeQuery"]) {
              peers.push(peerName);
          }
      }
  }
  logger.debug("all non endorsing chaincode query peers for channel "+ channelName +":", peers);
  return peers;
}


//return endorsing peers for the channel
function getEndorsingPeersForChannel(channelName) {
  //peers in channel config
  let peers = [];
  if (defaultNetworkConfig["channels"][channelName]) {
      for (let peerName in defaultNetworkConfig["channels"][channelName]["peers"]) {
          let peer = defaultNetworkConfig["channels"][channelName]["peers"][peerName];
          if (false !== peer["endorsingPeer"]) {
              peers.push(peerName);
          }
      }
  }
  logger.debug("all endorsing peers for channel "+ channelName +":", peers);

  return peers;
}

//return endorsing peers and chaincode query peers for the channel, org
function getPeersToInstallChaincodeForOrg(channelName, orgName) {
    //peers in channel config
    let peers = [];
    let peerNames = [];
    if (defaultNetworkConfig["channels"][channelName]) {
        for (let peerName in defaultNetworkConfig["channels"][channelName]["peers"]) {
            let peer = defaultNetworkConfig["channels"][channelName]["peers"][peerName];
            if (false !== peer["endorsingPeer"] || false !== peer["chaincodeQuery"]) {
                peers.push(peerName);
            }
        }
    }

    if (peers.length > 0) {
        //go over each orgs in organization config and check if the peers
        //are in the above list, and add it to the orgPeers list
        if (defaultNetworkConfig["organizations"][orgName]) {
            let orgPeers = defaultNetworkConfig["organizations"][orgName]["peers"];
            for (let i in orgPeers) {
                if (peers.includes(orgPeers[i])) {
                    peerNames.push(orgPeers[i]);
                }
            }
        }
    }
    logger.debug("all peers of org "+ orgName +" for channel "+ channelName +" need to have the chaincode:", peerNames);

    return peerNames;
}


//chiancodeType = golan, car, java, node
async function installChaincodeForOrg(peers, chaincodeName, chaincodePath,
                                      chaincodeVersion, chaincodeType, org_name, client) {
    logger.info('install changecode %s for org %s', chaincodeName+"."+chaincodeVersion, org_name);
    let error_message = null;
    try {
        let tx_id = client.newTransactionID(true); //get an admin transactionID
        var request = {
            targets: peers,
            chaincodePath: chaincodePath,
            chaincodeId: chaincodeName,
            chaincodeVersion: chaincodeVersion,
            chaincodeType: chaincodeType
        };

        logger.debug("installChaincode request:", request);
        let results = await client.installChaincode(request);
        // the returned object has both the endorsement results
        // and the actual proposal, the proposal will be needed
        // later when we send a transaction to the orederer
        var proposalResponses = results[0];
        var proposal = results[1];

        // lets have a look at the responses to see if they are
        // all good, if good they will also include signatures
        // required to be committed
        var all_good = true;
        for (var i in proposalResponses) {
            let one_good = false;
            if (proposalResponses[i] instanceof Error) {
                error_message = util.format('install proposal resulted in an error :: %s', proposalResponses[i].toString());
                logger.error(error_message);
            } else if (proposalResponses && proposalResponses[i].response &&
                proposalResponses[i].response.status === 200) {
                one_good = true;
                logger.info('install proposal was good:', proposalResponses[i].peer.name);
            } else {
                error_message = util.format('install proposal was bad for an unknown reason  %s: - %s, message - "%s"',
                        proposalResponses[i].peer.name, proposalResponses[i].response.status, proposalResponses[i].response.message);
                logger.error(error_message);
            }
            all_good = all_good & one_good;
            if (!all_good) {
                break;
            }
        }
        if (all_good) {
            logger.info('Successfully sent install Proposal and received ProposalResponse');
        }
    } catch(error) {
        logger.error('Failed to install due to error: ' + error.stack ? error.stack : error);
        error_message = error.toString();
    }

    if (!error_message) {
        let message = util.format('Successfully install chaincode');
        logger.info(message);
        // build a response to send back to the REST caller
        let response = {
            success: true,
            message: message
        };
        return response;
    } else {
        let message = util.format('Failed to install due to:%s',error_message);
        logger.error(message);
        throw new Error(message);
    }
}


//Instantiate or update chaincode for org
//instantiate type = "instantiate" or "update"
async function instantiateChaincode(instantiateType, peers, channelName, chaincodeName, chaincodeVersion, functionName, chaincodeType, args, endorse_policy, org_name, client) {
    logger.debug('instantiate chaincode %s.%s on channel ' + channelName, chaincodeName, chaincodeVersion);
    var error_message = null;
    var channel = null;
    
    try {
        channel = client.getChannel(channelName);
        if(!channel) {
            let message = util.format('Channel %s was not defined in the connection profile', channelName);
            logger.error(message);
            throw new Error(message);
        }
        // Get an admin based transactionID
        // An admin based transactionID will
        // indicate that admin identity should
        // be used to sign the proposal request.
        const tx_id = client.newTransactionID(true);

        // will need the transaction ID string for the event registration later
        const deployId = tx_id.getTransactionID();

        // send proposal to endorser
        const request = {
            targets : peers,
            chaincodeId: chaincodeName,
            chaincodeType: chaincodeType,
            chaincodeVersion: chaincodeVersion,
            args: args,
            txId: tx_id
        };

        if (endorse_policy) {
            request["endorsement-policy"] = endorse_policy;
        }
        
        if (functionName)
            request.fcn = functionName;

        logger.debug(request);

        //instantiate takes much longer
        var results = null;
        let timeout = parseInt(hfc.getConfigSetting('instantiateProposalTimeout'));
        if (instantiateType === "instantiate") {
            results = await channel.sendInstantiateProposal(request, timeout);
        } else if (instantiateType === "update") {
            results = await channel.sendUpgradeProposal(request, timeout);
        } else {
            throw new Error("Unknown Instantiate Type: "+instantiateType);
        }


        // the returned object has both the endorsement results
        // and the actual proposal, the proposal will be needed
        // later when we send a transaction to the orderer
        var proposalResponses = results[0];
        var proposal = results[1];

        // lets have a look at the responses to see if they are
        // all good, if good they will also include signatures
        // required to be committed
        var all_good = true;
        for (var i in proposalResponses) {
            if (proposalResponses[i] instanceof Error) {
                all_good = false;
                error_message = util.format('instantiate proposal resulted in an error :: %s', proposalResponses[i].toString());
                logger.error(error_message);
            } else if (proposalResponses && proposalResponses[i].response &&
                proposalResponses[i].response.status === 200) {
                logger.info('instantiate proposal was good', proposalResponses[i].peer.name);
            } else {
                all_good = false;
                error_message = util.format('instantiate proposal was bad instantiate %s: - %s, message - "%s"',
                        proposalResponses[i].peer.name, proposalResponses[0].response.status, proposalResponses[0].response.message);
                logger.error(error_message);
            }
        }

        if (all_good) {
            logger.info(util.format(
                'Successfully sent Proposal and received ProposalResponse: Status - %s, message - "%s"',
                proposalResponses[0].response.status, proposalResponses[0].response.message));

            // wait for the channel-based event hub to tell us that the
            // instantiate transaction was committed on the peer
            var promises = [];
            //let event_hubs = channel.getChannelEventHubsForOrg();
            //let event_hubs = client.getEventHubsForOrg(org_name);
            let event_hubs = null;
            if (hfc.getConfigSetting(ConfigKeys.fabric_version) >= SolutionConfigValues.fabric11_Dev_Version) {
                let mspid = getMspidOfOrg(org_name);
                event_hubs = channel.getChannelEventHubsForOrg(org_name);
            } else {
                event_hubs = client.getEventHubsForOrg(org_name);
            }

            logger.debug('found %s eventhubs',event_hubs.length);
            event_hubs.forEach((eh) => {
                let instantiateEventPromise = new Promise((resolve, reject) => {
                    logger.debug('instantiateEventPromise - setting up event');
                    let event_timeout = setTimeout(() => {
                        let message = 'REQUEST_TIMEOUT:' + eh.getPeerAddr();
                        logger.error(message);
                        eh.disconnect();
                    }, 60000);
                    eh.registerTxEvent(deployId, (tx, code) => {
                            logger.info('The chaincode instantiate transaction has been committed on peer %s',eh.getPeerAddr());
                            //logger.info('Transaction %s has status of %s in block %s', tx, code, block_num);
                            clearTimeout(event_timeout);

                            if (code !== 'VALID') {
                                let message = until.format('The chaincode instantiate transaction was invalid, code:%s',code);
                                logger.error(message);
                                reject(new Error(message));
                            } else {
                                let message = 'The chaincode instantiate transaction was valid.';
                                logger.info(message);
                                resolve(message);
                            }
                        }, (err) => {
                            clearTimeout(event_timeout);
                            logger.error(err);
                            reject(err);
                        },
                        // the default for 'unregister' is true for transaction listeners
                        // so no real need to set here, however for 'disconnect'
                        // the default is false as most event hubs are long running
                        // in this use case we are using it only once
                        {unregister: true, disconnect: true}
                    );
                    eh.connect();
                });
                promises.push(instantiateEventPromise);
            });

            var orderer_request = {
                txId: tx_id, // must include the transaction id so that the outbound
                             // transaction to the orderer will be signed by the admin
                             // id as was the proposal above, notice that transactionID
                             // generated above was based on the admin id not the current
                             // user assigned to the 'client' instance.
                proposalResponses: proposalResponses,
                proposal: proposal
            };
            var sendPromise = channel.sendTransaction(orderer_request);
            // put the send to the orderer last so that the events get registered and
            // are ready for the orderering and committing
            promises.push(sendPromise);
            let results = await Promise.all(promises);
            let response = results.pop(); //  orderer results are last in the results
            if (response.status === 'SUCCESS') {
                logger.info('Successfully sent transaction to the orderer.');
            } else {
                error_message = util.format('Failed to order the transaction. Error code: %s',response.status);
                logger.debug(error_message);
            }

            // now see what each of the event hubs reported
            /*
            for(let i in results) {
                let event_hub_result = results[i];
                let event_hub = event_hubs[i];
                logger.debug('Event results for event hub :%s',event_hub.getPeerAddr());
                if(typeof event_hub_result === 'string') {
                    logger.debug(event_hub_result);
                } else {
                    if(!error_message) error_message = event_hub_result.toString();
                    logger.debug(event_hub_result.toString());
                }
            }
            */
        } else {
            error_message = util.format('Failed to send Proposal and receive all good ProposalResponse');
            logger.debug(error_message);
        }


    } catch (error) {
        logger.error('Failed to send instantiate due to error: ' + error.stack ? error.stack : error);
        error_message = error.toString();
    } finally {
        if (channel) {
            channel.close();
        }
    }

    if (!error_message) {
        let message = util.format(
            'Successfully instantiate chaincode in organization %s to the channel \'%s\'',
            org_name, channelName);
        logger.info(message);
        // build a response to send back to the REST caller
        let response = {
            success: true,
            message: message
        };
        return response;
    } else {
        let message = util.format('Failed to instantiate. cause:%s',error_message);
        logger.error(message);
        throw new Error(message);
    }
}



async function invokeInit(solutionName, attrList) {
    // invoke init()
    // get app admin config
    let adminConfig = defaultSolutionConfig["solutions"][solutionName]["app_admin"];
    let adminOrg = adminConfig["org"];
    let adminId = adminConfig["username"];
    let adminSecret = adminConfig["secret"];

    let chaincodeConfig = defaultSolutionConfig["solutions"][solutionName]["chaincode"];
    let chaincodeName = chaincodeConfig["name"];

    let channelConfig = defaultSolutionConfig["solutions"][solutionName]["channels"];

    // get client
    let client = await getClientForOrg(adminOrg, adminId, adminSecret);

    // TMap
    let username64 = new Buffer(adminId).toString('base64');
    var tmap = {
        id: username64,
        prvkey: "",
        pubkey: "",
        symkey: ""
    };
    // get keys from attrlist
    for (let i = 0; i < attrList.length; i++) {
        let attr = attrList[i];
        if (attr["name"] === "prvkey") {
            tmap["prvkey"] = attr["value"];
        } else if (attr["name"] === "pubkey") {
            tmap["pubkey"] = attr["value"];
        } else if (attr["name"] === "symkey") {
            tmap["symkey"] = attr["value"];
        }
    }

    // AppAdmin user object
    let appAdminObj = {
        id: adminId,
        name: adminId,
        role: "system",
        status: "active",
        secret: adminSecret,
        public_key: tmap["pubkey"],
        private_key: tmap["prvkey"],
        sym_key: tmap["symkey"],
        is_group: false,
        email: "TODO",
        kms_public_key_id: "none",
        kms_private_key_id: "none",
        kms_sym_key_id: "none"
    };

    let args = [JSON.stringify(appAdminObj)];
    let fcn = "init";

    for (let channelName in channelConfig) {
        logger.info("Invoke init for "+solutionName+" for channel "+channelName);
        let response = await invokePHI(adminId, adminSecret, channelName, chaincodeName, fcn, [], args, tmap, adminOrg, client);
    }

    logger.info("Invoke init for "+ solutionName+" done successfully");
    return true;
}

exports.getUserAttributes = getUserAttributes;
async function getUserAttributes(username, userSecret, attrReqs, userOrg) {
    logger.debug("Getting user attributes:", username, attrReqs);

    try {
        // attempt to get from cache first
        let cacheKey = username + "_keys"
        let userKeys = await getData(cacheKey);
        if (!userKeys) {
            let caClient = await getCaClientForOrg(userOrg);
            let req = {enrollmentID: username, enrollmentSecret: userSecret, profile: "tls", attr_reqs: attrReqs};
            let enrollment = await caClient.enroll(req);
            let amap = getAttributesFromEnrollCert(enrollment.certificate, false);

            // update cache
            await setData(cacheKey, JSON.stringify(amap["attrs"]));

            return amap["attrs"];
        } else {
            logger.debug("Retrieved user keys from cache for user: ", username);
            return JSON.parse(userKeys);
        }
    } catch (err) {
        logger.debug("Error invoking Redis: ", err);
        return null;
    }
}

function getAttributesFromCert(certificate, encode) {
    var attribute_map = {};
    try {
        var parsedCertificate = x509.parseCert(certificate);

        // fabric-ca uses 1.2.3.4.5.6.9 extension to store the names and locations of the attributes in the cert
        // in this form: attrName1->1#attrName2->2#
        // these will not necessarily be in order
        var keys = parsedCertificate.extensions['1.2.3.4.5.6.9'];
        var attrNames = keys.split('#');

        var attrName;
        var extensionKey;
        var extensionValue;
        attrNames.slice(0, attrNames.length - 1).forEach((pair) => {
            attrName = pair.split('->')[0];

            // fabric-ca stores attribues at extensions called 1.2.3.4.5.6.x where x is 10 for the first
            // attributes and increments for each subsequent attribute
            extensionKey = '1.2.3.4.5.6.' + (parseInt(pair.split('->')[1]) + 9);
            extensionValue = parsedCertificate.extensions[extensionKey];

            if (encode) {
                extensionValue = new Buffer(extensionValue).toString('base64');
            }

            attribute_map[attrName] = extensionValue;
        });
    } catch (err) {
        debug.error("fail to get attributes:", err);
        attribute_map = {}
    }
    return attribute_map;
}

exports.getAttributesFromEnrollCert = getAttributesFromEnrollCert;
function getAttributesFromEnrollCert(certificate, encode) {
    var attribute_map = {};
    try {
        var parsedCertificate = x509.parseCert(certificate);

        //fabric CA saves attributes under 1.2.3.4.5.6.7.8.1 extension key
        let enCertExt = parsedCertificate.extensions["1.2.3.4.5.6.7.8.1"];
        attribute_map = JSON.parse(enCertExt);
    } catch (err) {
        logger.error("fail to get attributes:", err);
        attribute_map = {}
    }
    return attribute_map
}

function buildErrorJson(chaincodeError){
    let errorMessage = chaincodeError.toString();
    if (errorMessage.includes("message: ")) {
        errorMessage = errorMessage.split("message: ")[1].slice(0,-1);
    }
    var errorStatusAndMessageJSON = null;
    //validating status code is number between 100 and 511 (range of http error codes)
    let statusCodeVal = errorMessage.split("::")[0];
    let isnum = /^\d+$/.test(statusCodeVal);
    let statusCodeValid = isnum === true ? parseInt(statusCodeVal) >= 100 && parseInt(statusCodeVal) <= 511 : false;
    //error message doesn't contain :: <http-error-code>::<message> so we assume 500 internal server error
    if(!errorMessage.includes("::") || !statusCodeValid){
        errorStatusAndMessageJSON = {status: 500,message: errorMessage}
    }else{
        let errorStatusAndMessageArray = errorMessage.split("::");
        errorStatusAndMessageJSON = {status: errorStatusAndMessageArray[0],message: errorStatusAndMessageArray[1]}
    }
    return errorStatusAndMessageJSON;
}


module.exports.invokePHI =invokePHI;
async function invokePHI(username, usersecret, channelName, chaincodeName, fcn, args, phi_args, tmap, org, client) {
    if (!tmap) {
        tmap = {};
    }
    if (!args) {
        args = [];
    }
    if (phi_args.length > 0) {
        for (let i = 0; i < phi_args.length; i++) {
            let key = "arg"+i;
            let val = new Buffer(phi_args[i]).toString('base64');
            let hash = kms.getHash(phi_args[i]);
            args.push(hash);
            tmap[key] = val
            logger.debug("PHI args hash:", key, hash);
        }
        tmap["num_args"] = new Buffer(''+phi_args.length).toString('base64');
    }
    return invoke(username, usersecret, channelName, chaincodeName, fcn, args, tmap, org, client, false);
}

module.exports.invoke = invoke;
async function invoke(username, usersecret, channelName, chaincodeName, fcn, args, tmap, org, client, retry) {
    let client2 = null;
    if (!client) {
        client2 = await getClientForOrg(org, username, usersecret);
    } else {
        client2 = client;
    }
    
    if (!retry) {
        retry = false;
    }

    logger.info("==> sending invoke function:", fcn, ", caller:", username, ", channel:", channelName, ", chaincodeName:", chaincodeName);

    if (!tmap) {
        tmap = {};
    }
    if (!tmap["id"]) {
        let attr_reqs = [];
        attr_reqs.push( {name: "id"} );
        attr_reqs.push( {name: "prvkey"} );
        attr_reqs.push( {name: "pubkey"} );
        attr_reqs.push( {name: "symkey"} );
        let amap = await getUserAttributes(username, usersecret, attr_reqs, org);
        if (!amap) {
            // TODO: handle this error in the future
            throw new Error("Failed to get user attributes");
        }

        let symkey64 = amap["symkey"];
        let prvkey64 = amap["prvkey"];
        let pubkey64 = amap["pubkey"];
        let username64 = new Buffer(username).toString('base64');
        
        tmap["id"] = username64;
        tmap["prvkey"] = prvkey64;
        tmap["pubkey"] = pubkey64;
        tmap["symkey"] = symkey64;
    }

    // set peerNames to peers within org only if endorsement policy is "OR" to save time.
    let peerNames = [];
    let endorsePolicy = hfc.getConfigSetting('endorsement_policy') || 'AND';

    if (endorsePolicy.toLowerCase() === 'or') {
        peerNames = getPeersToInstallChaincodeForOrg(channelName, org);
    }
    logger.debug("peers:", peerNames);

    try {
        let response =  await invokeChaincode(peerNames, channelName, chaincodeName, fcn, args, tmap, username, org, client2);
        logger.info("<== invoke completed success: function:", fcn, ", caller:", username, ", channel:", channelName, ", chaincodeName:", chaincodeName );
        return response;
    } catch (err) {
        logger.warn("<== invoke failed: function:", fcn, ", caller:", username, ", channel:", channelName, ", chaincodeName:", chaincodeName, ", error:", err );
        if (!retry) {
            logger.info("retry calling invoke "+fcn);
            return await invoke(username, usersecret, channelName, chaincodeName, fcn, args, tmap, org, client2, true);
        } else {
            logger.error("<== invoke failed: function:", fcn, ", caller:", username, ", channel:", channelName, ", chaincodeName:", chaincodeName, ", error:", err );
            var errmsg = util.format("invoke "+fcn+" failed: %s", err);
            if(err.toString().toLowerCase().includes('error')){
                let chaincodeErrorJson = buildErrorJson(err);
                throw new Error(JSON.stringify(chaincodeErrorJson));
            } else {
                throw new Error(errmsg);
            }
        }
    }
}


async function invokeChaincode(peerNames, channelName, chaincodeName, fcn, args, tmap, username, org_name, client) {
    var error_message = null;
    var tx_id_string = null;
    let response_data = null;
    let channel = null;
    try {
        // first setup the client for this org
        let client2 = null;
        if (!client) {
            client2 = await getClientForOrg(org_name, username);
        } else {
            client2 = client;
        }
        logger.debug('Successfully got the fabric client for the organization "%s"', org_name);
        channel = client2.getChannel(channelName);
        if(!channel) {
            let message = util.format('Channel %s was not defined in the connection profile', channelName);
            logger.error(message);
            throw new Error(message);
        }
        var tx_id = client2.newTransactionID();
        // will need the transaction ID string for the event registration later
        tx_id_string = tx_id.getTransactionID();

        // send proposal to endorser
        var request = {
            chaincodeId: chaincodeName,
            fcn: fcn,
            args: args,
            chainId: channelName,
            txId: tx_id
        };

        if (tmap) {
            request.transientMap = tmap;
        }

        if (peerNames && peerNames.length > 0) {
            const engine = loadbalance.random(peerNames)
            const pick = engine.pick()
            
            request.targets = [pick];
        }

        logger.info("Invoke for the function: " + fcn);
        let timeout = parseInt(hfc.getConfigSetting('transactionProposalTimeout'));
        let results = await channel.sendTransactionProposal(request, timeout);

        // the returned object has both the endorsement results
        // and the actual proposal, the proposal will be needed
        // later when we send a transaction to the orderer
        var proposalResponses = results[0];
        var proposal = results[1];

        // look at the responses to see if they are all are good
        // response will also include signatures required to be committed
        let all_good = true;
        for (const i in proposalResponses) {
            if (proposalResponses[i] instanceof Error) {
                all_good = false;
                error_message = util.format('invoke chaincode proposal resulted in an error :: %s', proposalResponses[i].toString());
                logger.error(error_message);
                break;
            } else if (proposalResponses[i].response && proposalResponses[i].response.status === 200) {
                logger.info('invoke chaincode proposal was good:', proposalResponses[i].peer.name);
            } else {
                all_good = false;
                error_message = util.format(
                        'invoke chaincode proposal failed for an unknown reason %s: - %s, message - "%s"',
                        proposalResponses[i].peer.name, proposalResponses[i].response.status, proposalResponses[i].response.message);
                logger.error(error_message);
                break;
            }
        }

        if (all_good) {
            response_data = proposalResponses[0].response.payload;
            logger.info(util.format(
                'Successfully sent Proposal and received ProposalResponse: Status - %s, message - "%s"',
                proposalResponses[0].response.status, proposalResponses[0].response.message));

            // wait for the channel-based event hub to tell us
            // that the commit was good or bad on each peer in our organization
            var promises = [];

            var eventWaitTime =  parseInt(hfc.getConfigSetting('eventWaitTime'));
            let event_hubs = await channel.getChannelEventHubsForOrg();

            event_hubs.forEach((eh) => {
                logger.debug('invokeEventPromise - setting up event');
                let invokeEventPromise = new Promise((resolve, reject) => {
                    let event_timeout = setTimeout(() => {
                        let message = 'REQUEST_TIMEOUT:' + eh.getPeerAddr();
                        logger.error(message);
                        eh.disconnect();
                    }, eventWaitTime);
                    eh.registerTxEvent(tx_id_string, (tx, code, block_num) => {
                            logger.debug('The chaincode invoke chaincode transaction has been committed on peer %s',eh.getPeerAddr());
                            logger.debug('Transaction %s has status of %s in block %s on peer %s', tx, code, block_num, eh.getPeerAddr());
                            clearTimeout(event_timeout);

                            if (code !== 'VALID') {
                                let message = util.format('The invoke chaincode transaction was invalid on %s, code:%s',eh.getPeerAddr(),code);
                                reject(new Error(message));
                            } else {
                                let message = util.format('The invoke chaincode transaction was valid on %s', eh.getPeerAddr());
                                resolve(message);
                            }
                        }, (err) => {
                            clearTimeout(event_timeout);
                            logger.error(err);
                            reject(err);
                        },
                        // the default for 'unregister' is true for transaction listeners
                        // so no real need to set here, however for 'disconnect'
                        // the default is false as most event hubs are long running
                        // in this use case we are using it only once
                        {unregister: true, disconnect: false}
                    );
                    eh.connect();
                });
                promises.push(invokeEventPromise);
            });

            var orderer_request = {
                txId: tx_id,
                proposalResponses: proposalResponses,
                proposal: proposal
            };

            var sendPromise = channel.sendTransaction(orderer_request, eventWaitTime);

            // put the send to the orderer last so that the events get registered and
            // are ready for the orderering and committing
            promises.push(sendPromise);
            let results = await Promise.all(promises);

            logger.info(util.format('orderer R E S P O N S E : %j', results));
            let response = results.pop(); //  orderer results are last in the results
            if (response && response.status === 'SUCCESS') {
                logger.info('Successfully sent transaction to the orderer.');
                let message = util.format('Successfully invoked the chaincode \'%s\' function \'%s\' to the channel \'%s\' for transaction ID: %s', chaincodeName, fcn, channelName, tx_id_string);
                logger.info(message);
                if(response_data.length>0) {
                    response_data = JSON.parse(response_data.toString('utf-8'));
                } else {
                    response_data = null;
                }
                return {'tx_id': tx_id_string, 'data': response_data};
            } else {
                error_message = util.format('Failed to order the transaction. Error code: %s',response.status);
                logger.debug(error_message);
            }
            
            // PLEAE DO NOT REMOVE FOLLOWING COMMENTED CODE
            // now see what each of the event hubs reported
            /*
            for(let i in results) {
                let event_hub_result = results[i];
                let event_hub = event_hubs[i];
                logger.info('Event results for event hub :%s',event_hub.getPeerAddr());
                if(typeof event_hub_result === 'string') {
                    logger.info(event_hub_result);
                } else {
                    if(!error_message) error_message = event_hub_result.toString();
                    logger.info(event_hub_result.toString());
                }
            }
            */
            
        }
    } catch (error) {
        logger.error('Failed to invoke due to error: ' + error.stack ? error.stack : error);
        error_message = error.toString();
    } finally {
        if (channel) {
            channel.close();
        }
    }

    if (!error_message) {
        let message = util.format('Successfully invoked the chaincode \'%s\' function \'%s\' to the channel \'%s\' for transaction ID: %s', chaincodeName, fcn, channelName, tx_id_string);
        logger.info(message);
        return { 'tx_id': tx_id_string}
    } else {
        let message = util.format('Failed to invoke chaincode. cause: %s',error_message);
        logger.error(message);
        throw new Error(message);
    }
}


module.exports.query = query;
async function query(username, usersecret, channelName, chaincodeName, fcn, args, tmap, org, client, retry) {
    
    let client2 = null;
    if (!client) {
        client2 = await getClientForOrg(org, username, usersecret);
    } else {
        client2 = client
    }
    let caClient = client2.getCertificateAuthority();  //----- yoon
    if (!retry) {
        retry = false;
    }

    logger.info("==> sending query function:", fcn, ", caller:", username, ", channel:", channelName, ", chaincodeName:", chaincodeName);

    if (!tmap) {
        let attr_reqs = [];
        attr_reqs.push( {name: "id"} );
        attr_reqs.push( {name: "prvkey"} );
        attr_reqs.push( {name: "pubkey"} );
        attr_reqs.push( {name: "symkey"} );
        let amap = await getUserAttributes(username, usersecret, attr_reqs, org);
        if (!amap) {
            // TODO: handle this error in the future
            throw new Error("Failed to get user attributes");
        }

        let symkey64 = amap["symkey"];
        let prvkey64 = amap["prvkey"];
        let pubkey64 = amap["pubkey"];
        let username64 = new Buffer(username).toString('base64');
        tmap = {
            id: username64,
            prvkey: prvkey64,
            pubkey: pubkey64,
            symkey: symkey64
        };
    }

    // compute target peers based on query_option
    let peerNames = [];
    let default_option = {
            number_of_peers_to_send_query: 1,
            use_non_endorsing_peers_first: true
    };
    let query_option = hfc.getConfigSetting("query_option") ? hfc.getConfigSetting("query_option") : default_option;
    let num_query_peers = query_option["number_of_peers_to_send_query"] ? query_option["number_of_peers_to_send_query"] : 1;
    let non_endorser_first = false === query_option["use_non_endorsing_peers_first"] ? false : true;
        
    let peers = getPeersToInstallChaincodeForChannel(channelName);
    if (num_query_peers >= peers.length) {
        peerNames = [];
    } else if (!non_endorser_first) {
        shuffle(peers);
        peerNames = peers.slice(0,num_query_peers);
    } else {
        //non endorsing peers first
        let non_endorsing_peers = getNonEndorsingQueryPeersForChannel(channelName);
        if (num_query_peers < non_endorsing_peers.length) {
            shuffle(non_endorsing_peers);
            peerNames = non_endorsing_peers.slice(0,num_query_peers);
        } else {
            let end_peers = getEndorsingPeersForChannel(channelName);
            shuffle(end_peers);
            peerNames = non_endorsing_peers.concat(end_peers.slice(0,num_query_peers-non_endorsing_peers.length));
        }
    }
    logger.info("target peers:", peerNames);

    try {
        let result =  await queryChaincode(peerNames, channelName, chaincodeName, fcn, args, tmap, username, org, client2);

        var value;
        try {
            if(result.length!=0) {
                value = JSON.parse(result);
            }
            logger.info("<== query completed: fcn:", fcn, ", caller:", username, ", ch:", channelName, ", cc:", chaincodeName); 
            return value;    
        }
        catch (err) {
            logger.warn(
                err.toString().includes("SyntaxError") 
                ? "SyntaxError in result "+result 
                : err);
            throw err;
        }
        

    } catch (err) {
        logger.warn("  <== query failed: fcn:", fcn, ", caller:", username, ", ch:", channelName, ", cc:", chaincodeName, ", error:", err );
        if (!retry) {
            logger.info("retry calling query "+fcn);
            return await query(username, usersecret, channelName, chaincodeName, fcn, args, tmap, org, client, true);
        } else {
            logger.error("<== query failed: fcn:", fcn, ", caller:", username, ", ch:", channelName, ", cc:", chaincodeName, ", error:", err );
            var errmsg = util.format("query "+fcn+" failed: %s", err);            
            logger.error(errmsg, err);
            if(err.toString().toLowerCase().includes('error')){
                let chaincodeErrorJson = buildErrorJson(err);
                throw new Error(JSON.stringify(chaincodeErrorJson));
            } else {
                throw new Error(errmsg);
            }
        }
    }
}


async function queryChaincode(peerNames, channelName, chaincodeName, fcn, args, tmap, username, org_name, client) {
    var channel = null;
    try {
        // first setup the client for this org
        let client2 = null;
        if (!client) {
            client2 = await getClientForOrg(org_name, username);
        } else {
            client2 = client;
        }
        logger.debug('Successfully got the fabric client for the organization "%s"', org_name);
        channel = client2.getChannel(channelName);
        if(!channel) {
            let message = util.format('Channel %s was not defined in the connection profile', channelName);
            logger.error(message);
            throw new Error(message);
        }

        // send query
        var request = {
            chaincodeId: chaincodeName,
            fcn: fcn,
            args: args
        };

        if (tmap) {
            request.transientMap = tmap;
        }
        if (peerNames && peerNames.length > 0) {
            request.targets = peerNames;
        }

        logger.info("Query for the function: " + fcn);
        let response_payloads = await channel.queryByChaincode(request);

        logger.debug("Number of response payloads:", response_payloads.length);
        if (response_payloads && response_payloads.length > 0) {
            let error_response = null;
            for (let i = 0; i < response_payloads.length; i++) {
                if(response_payloads[i].toString('utf8').toLowerCase().includes('error')){
                    logger.error("got error from chaincode");
                    error_response = response_payloads[i].toString('utf8');
                } else {
                    logger.info("Successfully got query response")
                    return response_payloads[i];
                }
            }
            throw new Error(error_response);
        } else {
            var errmsg = 'response_payloads is null';
            logger.error(errmsg);
            throw new Error(errmsg);
        }

    } catch(error) {
        logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
        throw error;
    } finally {
        if (channel) {
            channel.close();
        }
    }
}


module.exports.getChainInfo = getChainInfo;
async function getChainInfo(username, secret, org_name, channelName, client) {

    // first setup the client for this org
    let client2 = null;
    if (!client) {
        client2 = await getClientForOrg(org_name, username);
    } else {
        client2 = client;
    }
    logger.debug('Successfully got the fabric client for the organization "%s"', org_name);
    var channel = client2.getChannel(channelName);

    var blockchainInfo = await channel.queryInfo();

    logger.info("successfully got chain info : " + username + " " + org_name);
    return blockchainInfo;

}

module.exports.getBlockByNumber = getBlockByNumber;
async function getBlockByNumber(blockNumber, username, secret, org_name, channelName, client) {
    try {
        // first setup the client for this org
        // first setup the client for this org
        let client2 = null;
        if (!client) {
            client2 = await getClientForOrg(org_name, username);
        } else {
            client2 = client;
        }
        logger.debug('Successfully got the fabric client for the organization "%s"', org_name);
        var channel = client2.getChannel(channelName);
        if(!channel) {
            let message = util.format('Channel %s was not defined in the connection profile', channelName);
            logger.error(message);
            throw new Error(message);
        }

        let peers = getPeersToJoinChannelForOrg(channelName, org_name);
        let peer = null;
        if (peers.length > 0) {
            peer = peers[0];
        }
        let response_payload = await channel.queryBlock(parseInt(blockNumber, peer));
        if (response_payload) {
            return response_payload;
        } else {
            logger.error('response_payload is null');
            return 'response_payload is null';
        }
    } catch(error) {
        logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
        return error.toString();
    }
}

module.exports.getTransactionByID = getTransactionByID;
async function getTransactionByID(peer, channelName, trxnID, username, secret, org_name, client) {
    try {
        // first setup the client for this org
        let client2 = null;
        if (!client) {
            client2 = await getClientForOrg(org_name, username);
        } else {
            client2 = client;
        }
        logger.debug('Successfully got the fabric client for the organization "%s"', org_name);
        var channel = client2.getChannel(channelName);
        if(!channel) {
            let message = util.format('Channel %s was not defined in the connection profile', channelName);
            logger.error(message);
            throw new Error(message);
        }

        let response_payload = await channel.queryTransaction(trxnID, peer);
        if (response_payload) {
            logger.info("successfully got trasactionj for ID:", trxnID);
            return response_payload;
        } else {
            logger.error('response_payload is null');
            return 'response_payload is null';
        }
    } catch(error) {
        logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
        return error.toString();
    }
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        let j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
}

module.exports.getLogger = getLogger;
function getLogger(moduleName) {
    let logger = log4js.getLogger(moduleName);
    logger.level = log_level;
    return logger;
}