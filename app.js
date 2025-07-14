const dotenv = require("dotenv").config();
const kbpgp = require("kbpgp");
const fetch = require("node-fetch");
const express = require("express");
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();

app.use(express.json());
app.use(bodyParser.json());

const ENCRYPTION_ALGORITHM = 'aes-256-ctr';
const ENCRYPTION_KEY = Buffer.from('12c5704ae2af4203d97c2540307475a74e81f28385cb7955bea23641a5764acf', 'hex');
const IV = Buffer.from('a4e1112f45e84f785358bb86ba750f48', 'hex');

app.get('/', (req, res) => {
    res.send('This app support post endpoint only');
});

app.post("/", (req, res, next) => {

    if (!req.headers.authorization || req.headers.authorization.indexOf('Basic ') === -1) {
        return res.status(401).json({ message: 'Missing Authorization Header: Basic Auth' });
    }

    const base64Credentials = req.headers.authorization.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    const user = authenticate({ username, password });
    if (!user) {
        return res.status(401).json({ message: 'Invalid Authentication Credentials' });
    }

    // console.log(req.body);

    var body = req.body;
    var msg = body.xml;
    var issandbox = body.issandbox != null ? body.issandbox : false;
    var url = body.url;
    var apiType = body.apiType;

    var decodedXmlMsg = decodeURIComponent(msg);
    console.log("input is: " + decodedXmlMsg);
  console.log("apiType is: " + apiType);

    var publicKeyArmored = issandbox ? process.env.SANDBOX_RECEIVERS_PUBLIC_KEY : process.env.PROD_RECEIVERS_PUBLIC_KEY;
    var privateKeyArmored = issandbox ? process.env.SANDBOX_SIGNER_PRIVATE_KEY : process.env.PROD_SIGNER_PRIVATE_KEY;
    var passphrase = issandbox ? process.env.SANDBOX_SIGNER_PASSPHARSE : process.env.PROD_SIGNER_PASSPHARSE;

    kbpgp.KeyManager.import_from_armored_pgp(
        {
            armored: decrypt(privateKeyArmored),
        },
        function (err, currUser) {
            if (err) {
                console.log('error:' + err);
                next(err);
            }
            if (!err) {
                if (currUser.is_pgp_locked()) {
                    currUser.unlock_pgp(
                        {
                            passphrase: decrypt(passphrase),
                        },
                        function (err) {
                            if (err) {
                                console.log('error:' + err);
                                next(err);
                            }
                            if (!err) {
                                console.log("Loaded private key with passphrase");
                            }
                        }
                    );
                }
            }

            // import receiver's public key
            kbpgp.KeyManager.import_from_armored_pgp(
                {
                    armored: decrypt(publicKeyArmored),
                },
                function (err, receiver) {
                    if (err) {
                        console.log("error: " + err);
                        next(err);
                    }
                    if (!err) {
                        console.log("receiver's public key is loaded");

                        var params = {
                            msg: decodedXmlMsg,
                            sign_with: currUser,
                            encrypt_for: receiver,
                        };

                        kbpgp.box(params, function (err, result_string, result_buffer) {
                            if (err) {
                                console.log('error:' + err);
                                next(err);
                            }
                            if (!err) {
                                var pgpEncryptedMsg = result_string;

                                console.log("pgpEncryptedMsg: " + pgpEncryptedMsg);
                                if (pgpEncryptedMsg) {
                                    var base64EncodedData = Buffer.from(pgpEncryptedMsg).toString('base64');
                                    console.log("base64EncodedData: " + base64EncodedData);

                                    if(apiType == "payment"){
                                        var hsbcBodyObj = {
                                            paymentBase64: base64EncodedData
                                        }
                                    }
                                    if(apiType == "status"){
                                        var hsbcBodyObj = {
                                            paymentEnquiryBase64: base64EncodedData
                                        }
                                    }
                                    
                                    // var url = issandbox ? process.env.SANDBOX_HSBC_URL : process.env.PROD_HSBC_URL;
                                    var contentType = process.env.CONTENT_TYPE;
                                    var clientId = issandbox ? process.env.SANDBOX_HSBC_CLIENT_ID : process.env.PROD_HSBC_CLIENT_ID;
                                    var clientSecret = issandbox ? process.env.SANDBOX_HSBC_CLIENT_SECRET : process.env.PROD_HSBC_CLIENT_SECRET;
                                    var profileId = issandbox ? process.env.SANDBOX_HSBC_PROFILE_ID : process.env.PROD_HSBC_PROFILE_ID;
                                    var payloadType = process.env.PAYLOAD_TYPE;
                                  
                                  // console.log(decrypt(clientId))
                                  // console.log(decrypt(clientSecret))
                                  // console.log(decrypt(profileId))
                                  // console.log(decrypt(payloadType))
                                  // console.log(JSON.stringify(hsbcBodyObj))
                                  
                                  

                                    fetch(url, {
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': contentType,
                                            'x-hsbc-client-id': decrypt(clientId),
                                            'x-hsbc-client-secret': decrypt(clientSecret),
                                            'x-hsbc-profile-id': decrypt(profileId),
                                            'x-payload-type': decrypt(payloadType),
                                        },
                                        body: JSON.stringify(hsbcBodyObj)
                                    })
                                        .then(response => response.json())
                                        .then(response => {
                                            console.log(response);
                                            return res.status(200).json(response);
                                        })
                                        .catch(error => {
                                            console.log(error);
                                            return res.status(500).json(error);
                                        });
                                }
                            }
                        });
                    }
                }
            );
        }
    );
});

function authenticate({ username, password }) {
    if (username == decrypt(process.env.USR) && password == decrypt(process.env.USR_PWD)) {
        return true;
    }
    else {
        return false;
    }
}

function encrypt(value) {
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, IV);
    let encrypted = cipher.update(value, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(encryptedValue) {
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, IV);
    let decrypted = decipher.update(encryptedValue, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}

// listen for requests :)
const listener = app.listen(process.env.PORT, function () {
    console.log("Your app is listening on port " + listener.address().port);
});
