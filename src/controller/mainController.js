const axios = require('axios');
var path = require("path");
const crypto = require("crypto");
var MyInfoConnector = require("myinfo-connector-v4-nodejs");
const fs = require("fs");

var sessionIdCache = {};
const config = require("../config/config.js");
const connector = new MyInfoConnector(config.MYINFO_CONNECTOR_CONFIG);

const apiIndex = async function (req, res){
    res.status(200).json('Welcome to the SingPass Node API');
}

const apiCheck = async function (req, res){
    res.status(200).json('Welcome to the SingPass API');
}

const getEnv = async function (req, res){
  try {
    if (
      config.APP_CONFIG.DEMO_APP_CLIENT_ID == undefined ||
      config.APP_CONFIG.DEMO_APP_CLIENT_ID == null
    ) {
      res.status(500).send({
        error: "Missing Client ID",
      });
    } else {
      res.status(200).send({
        clientId: config.APP_CONFIG.DEMO_APP_CLIENT_ID,
        redirectUrl: config.APP_CONFIG.DEMO_APP_CALLBACK_URL,
        scope: config.APP_CONFIG.DEMO_APP_SCOPES,
        purpose_id: config.APP_CONFIG.DEMO_APP_PURPOSE_ID,
        authApiUrl: config.APP_CONFIG.MYINFO_API_AUTHORIZE,
        subentity: config.APP_CONFIG.DEMO_APP_SUBENTITY_ID,
      });
    }
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      error: error,
    });
  }
}

const getProfile = async function (req, res){
      const uinfin = req.body.uinfin;
      let config = {
        method: 'get',
        maxBodyLength: Infinity,
        url: 'https://sandbox.api.myinfo.gov.sg/com/v4/person-sample/'+uinfin,
        // params: {
        //     uinfin: uinfin
        // },
        headers: {}
      };

      try {
        const response = await axios.request(config);
        res.status(200).json(response.data);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user profile', message: error.message });
      }
}

module.exports = { apiIndex, apiCheck, getEnv, getProfile }