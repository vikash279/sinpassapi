const axios = require("axios");
var path = require("path");
const crypto = require("crypto");
// const generateJwkThumbprint = require("jwk-thumbprint");
var MyInfoConnector = require("myinfo-connector-v4-nodejs");
const fs = require("fs");
const qs = require("querystring");
const jose = require("jose");
const { createSign } = require("crypto");
const jwt = require('jsonwebtoken');
const { readFileSync } = require('fs');


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

const authorize = async function (req, res){
  try {
    const clientId = req.body.clientId;
    const scope = req.body.scope;
    const purpose_id = req.body.purpose_id;
    const method = "S256";
    const redirectUrl = req.body.redirectUrl;
    const authApiUrl = req.body.authApiUrl;
    let pkceCodePair = connector.generatePKCECodePair();
    var authorizeUrl = authApiUrl + "?client_id=" + clientId +
						"&scope=" + scope +
						"&purpose_id=" + purpose_id +
						"&code_challenge=" + pkceCodePair.codeChallenge +
						"&code_challenge_method=" + method +
						"&redirect_uri=" + redirectUrl;
    //res.status(200).send(pkceCodePair.codeChallenge);
    res.status(200).send(authorizeUrl);
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      error: error,
    });
  }
}

const getPersonData = async function (req, res){
  try{
    var authCode = req.body.authCode;
    var codeVerifier = req.body.codeVerifier;

    const privateKeyPath = path.resolve(__dirname, '../cert/your-sample-app-signing-private-key.pem');

    let privateSigningKey = fs.readFileSync(privateKeyPath, 'utf8');

    // let privateSigningKey = fs.readFileSync(
    //   config.APP_CONFIG.DEMO_APP_CLIENT_PRIVATE_SIGNING_KEY,
    //   "utf8"
    // );

    let privateEncryptionKeys = [];
    const privateKeyPathEncryption = path.resolve(__dirname, '../cert/encryption-private-keys/');
    // retrieve private encryption keys and decode to utf8 from FS, insert all keys to array
    console.log(privateKeyPathEncryption);
    readFiles(
      path.resolve(__dirname, '../cert/encryption-private-keys/'),
      (filename, content) => {
        privateEncryptionKeys.push(content);
      },
      (err) => {
        throw err;
      }
    );

    let personData = await connector.getMyInfoPersonData(
      authCode,
      codeVerifier,
      privateSigningKey,
      privateEncryptionKeys
    );

    res.status(200).send(personData); //return personData
  } catch (error) {
    console.log("---MyInfo NodeJs Library Error---".red);
    console.log(error);
    res.status(500).send({
      error: error,
    });
  }

}

const constant = {
  HTTP_METHOD: {
    POST: 'POST',
    GET: 'GET',
    // Add other HTTP methods as needed
  },
}

const getAccessToken = async function (req, res) {
  try {
    const authCode = req.body.authCode;
    const privateSigningKey = config.APP_CONFIG.DEMO_APP_CLIENT_PRIVATE_SIGNING_KEY;
    const codeVerifier = req.body.codeVerifier;

    const tokenUrl = config.MYINFO_CONNECTOR_CONFIG.TOKEN_URL;
    const redirectUrl = config.APP_CONFIG.DEMO_APP_CALLBACK_URL;
    const clientId = config.APP_CONFIG.DEMO_APP_CLIENT_ID;

    const cacheCtl = "no-cache";
    const contentType = "application/x-www-form-urlencoded";
    const method = constant.HTTP_METHOD.POST;
    const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    const sessionPopKeyPair = await generateEphemeralKey();
    const jktThumbprint = await generateJwkThumbprint(sessionPopKeyPair.publicKey);
    const clientAssertion = await generateClientAssertion(tokenUrl, clientId, privateSigningKey, jktThumbprint);

    // Assemble params for Token API
    const params = qs.stringify({
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: redirectUrl,
      client_id: clientId,
      code_verifier: codeVerifier,
      client_assertion_type: clientAssertionType,
      client_assertion: clientAssertion,
    });

    const ath = await generateAth(clientAssertion);
    const dPoP = await generateDpop(tokenUrl, ath, constant.HTTP_METHOD.POST, sessionPopKeyPair);

    const headers = {
      "Content-Type": contentType,
      "Cache-Control": cacheCtl,
      "DPoP": dPoP,
    };

    // Invoke Token API
    const response = await axios.post(tokenUrl, params, { headers });

    res.status(200).send(response.data);
  } catch (error) {
    console.log("Error".red, error);
    if (error.response && error.response.data) {
      console.log("Response data:", error.response.data);
    }
    res.status(500).send({
      error: error,
    });
  }
}

//function to read multiple files from a directory
function readFiles(dirname, onFileContent, onError) {
  fs.readdir(dirname, function (err, filenames) {
    if (err) {
      onError(err);
      return;
    }
    filenames.forEach(function (filename) {
      fs.readFile(path.join(dirname, filename), "utf8", function (err, content) {
        if (err) {
          onError(err);
          return;
        }
        onFileContent(filename, content);
      });
    });
  });
}



async function generateEphemeralKey() {
  let options = {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  };

  let ephemeralKeyPair = crypto.generateKeyPairSync('rsa', options);

  let ephemeralPublicKey = ephemeralKeyPair.publicKey;
  let privateKey = ephemeralKeyPair.privateKey;

  let ephemeralPublicKeyObject = {
    kty: 'RSA',
    publicKey: ephemeralPublicKey,
    privateKey: privateKey
  };

  ephemeralPublicKeyObject.use = 'sig';
  ephemeralPublicKeyObject.alg = 'RS256';

  return ephemeralPublicKeyObject;
}


async function generateJwkThumbprint(ephemeralPublicKey) {
  const hashAlgorithm = 'sha256';

  const publicKeyBuffer = Buffer.from(ephemeralPublicKey, 'utf8');
  const publicKeyHash = crypto.createHash(hashAlgorithm).update(publicKeyBuffer).digest();
  const jwkThumbprint = await base64url(publicKeyHash);

  return jwkThumbprint;
}

async function base64url(source) {
  let base64 = source.toString('base64');
  let base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return base64url;
}

async function generateClientAssertion(url, clientId, jwkThumbprint) {
  try {
    let now = Math.floor(Date.now() / 1000);

    let payload = {
      sub: clientId,
      jti: generateRandomString(40),
      aud: url,
      iss: clientId,
      iat: now,
      exp: now + 300,
      cnf: {
        jkt: jwkThumbprint,
      },
    };

    const privateKeyPath = path.resolve(__dirname, '../cert/your-sample-app-signing-private-key.pem');

    let privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    let jwtToken = await signJWT(payload, privateKey);
   // console.log('jwtToken', jwtToken);
    return jwtToken;
  } catch (error) {
    console.error('generateClientAssertion error', error);
    throw constant.ERROR_GENERATE_CLIENT_ASSERTION;
  }
}

async function signJWT(payload, privateKey) {
  const sign = createSign('RSA-SHA256');
  const header = { typ: 'JWT', alg: 'RS256' };
  const encodedHeader = await base64urls(JSON.stringify(header));
  const encodedPayload = await base64urls(JSON.stringify(payload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  sign.update(signatureInput);
  const signature = sign.sign(privateKey).toString('base64');
  const encodedSignature = base64urls(signature);
  const jwtToken = `${signatureInput}.${encodedSignature}`;
  return jwtToken;
}

async function generateAth(accessToken){
  let sha256AccessToken =  crypto.createHash('sha256').update(accessToken).digest();
  let base64URLEncodedHash = sha256AccessToken.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return base64URLEncodedHash;
}  

async function generateDpop(url, ath, method, sessionPopKeyPair) {
  try {
    let now = Math.floor(Date.now() / 1000);
    let payload = {
      htu: url,
      htm: method,
      jti: generateRandomString(40),
      iat: now,
      exp: now + 120,
    };

    // Required only for /Person resource call
    if (ath) payload.ath = ath;

   // let privateKey = convertPrivateKeyFormat(sessionPopKeyPair.privateKey);
    let publicKey = convertPublicKeyFormat(sessionPopKeyPair.publicKey);

    const privateKeyPath = path.resolve(__dirname, '../cert/your-sample-app-signing-private-key.pem');

    let privateKey = fs.readFileSync(privateKeyPath, 'utf8');

    let jwtToken = await signJWTS(payload, privateKey);
    return jwtToken;
  } catch (error) {
    console.error('generateDpop error', error);
    throw constant.ERROR_GENERATE_DPOP;
  }
}

function convertPrivateKeyFormat(privateKey) {
  const PKCS8_HEADER = '-----BEGIN PRIVATE KEY-----';
  const PKCS8_FOOTER = '-----END PRIVATE KEY-----';
  const PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----';
  const PEM_FOOTER = '-----END RSA PRIVATE KEY-----';

  if (privateKey.includes(PKCS8_HEADER) && privateKey.includes(PKCS8_FOOTER)) {
    privateKey = privateKey.replace(PKCS8_HEADER, PEM_HEADER);
    privateKey = privateKey.replace(PKCS8_FOOTER, PEM_FOOTER);
  }

  return privateKey;
}

function convertPublicKeyFormat(publicKey) {
  const SPKI_HEADER = '-----BEGIN PUBLIC KEY-----';
  const SPKI_FOOTER = '-----END PUBLIC KEY-----';

  if (publicKey.includes(SPKI_HEADER) && publicKey.includes(SPKI_FOOTER)) {
    publicKey = publicKey.replace(SPKI_HEADER, '');
    publicKey = publicKey.replace(SPKI_FOOTER, '');
    publicKey = publicKey.replace(/[\n\r]/g, '');
  }

  return publicKey;
}

async function signJWTS(payload, privateKey) {
  try {
    const privateKeyPath = path.resolve(__dirname, '../cert/your-sample-app-signing-private-key.pem');
    const privateKeyData = readFileSync(privateKeyPath, 'utf8');

    const signOptions = {
      algorithm: 'ES256',
     // passphrase: '', // Optional passphrase if the private key is encrypted
    };

    const jwtToken = await jwt.sign(payload, privateKeyData, signOptions);
    return jwtToken;
  } catch (error) {
    console.error('signJWTS error', error);
    throw constant.ERROR_SIGN_JWTS;
  }
}



async function base64urls(source) {
  let base64 = Buffer.from(source).toString('base64');
  let base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return base64url;
}

function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
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

module.exports = { apiIndex, apiCheck, getEnv, authorize, getAccessToken, getPersonData, getProfile }