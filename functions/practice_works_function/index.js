
const express = require('express');
const catalystSDK = require("zcatalyst-sdk-node");

const { insertRow, getRow } = require("./catalystFunction");
const { omit, has, values, find } = require("lodash");

const bcrypt = require("bcrypt");
const passport = require("passport");
const initializaPassport = require("./passportConfig");

const crypto = require('crypto');
const secretKey = 'catalyst';
const algorithm = 'aes-256-cbc'; //Using AES encryption

const nodeRSA = require("node-rsa");
const key = new nodeRSA({b: 512});
key.setOptions({encryptionScheme: 'pkcs1'});


const app = express();
app.use(express.json());

app.use((req, res, next) => {
  const catalyst = catalystSDK.initialize(req);
  res.locals.catalyst = catalyst;
  next();
});

// todo check in login
app.post('/login', async (req, res) => {
	const catalyst = res.locals.catalyst;
	const zcql = catalyst.zcql();
  const email_id = req.body.l_email;
  const password = req.body.l_password;
  let query, queryResponse, subQuery, subQueryResponse;
  try {

    query = `SELECT UserDetails.Password FROM UserDetails WHERE UserDetails.Email = '${email_id}'`;
    console.log(query);
    queryResponse = await zcql.executeZCQLQuery(query);
    
    let db_password = queryResponse[0].UserDetails['Password'];
    console.log('queryResp: ',db_password);
    if (db_password) {
      // const hashedPassword = await bcrypt.hash(password, 15);
      // console.log(hashedPassword);

      
      let decryptedPassData = key.decryptPublic(db_password, "utf8");
      console.log(decryptedPassData);

      subQuery = `SELECT UserDetails.ROWID FROM UserDetails WHERE UserDetails.Email = '${email_id}' AND UserDetails.Password = '${password}'`;
      subQueryResponse = await zcql.executeZCQLQuery(subQuery);

      if (subQueryResponse.length) {
        console.log("🚀 Logged in successfully...");
        res.status(200).send({ message: "Logged in!" });
        // res.redirect("/app/assets/templates/index.html");
      } else {
        res.status(400).send({ message: "Password incorrect!" });
      }
    } else {
      res.status(400).send({ message: "No data found!" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send(err);
  }
});

app.post("/register", async (req, res) => {
  const catalyst = res.locals.catalyst;
  const zcql = catalyst.zcql();
  const user_name = req.body.user_name;
  const email_id = req.body.email;
  const password = req.body.password;
  const confirm_pass = req.body.confirm_password;
  let query, queryResponse, userDetailInserData;

  try {
    // const hashedPassword = await bcrypt.hash(password, 10);
    // const hashedConfirmPassword = await bcrypt.hash(confirm_pass, 10);
    
    let encryptedPassData = key.encrypt(password, 'base64');
    let encryptedConfirmPassData = key.encrypt(confirm_pass, 'base64');

    userDetailInserData = {
      UserName: user_name,
      Email: email_id,
      Password: encryptedPassData,
      ConfirmPassword: encryptedConfirmPassData
    };
  } catch(err) {
    console.log(err);
    res.status(500).send(err);
  }
  
  try {
    query = `SELECT UserDetails.ROWID FROM UserDetails WHERE UserDetails.Email = '${email_id}'`;
    queryResponse = await zcql.executeZCQLQuery(query);
    if (queryResponse.length) {
      res.status(400).send({ message: "User already exists!" });
    } else {
      if(password != confirm_pass) {
        res.status(200).send({ message: "Password mismatch!" });
      }
      insertRow(catalyst, "UserDetails", userDetailInserData).catch((err) => {
        console.log(err);
        res.status(500).send(err);
      });
      console.log("🚀 New user is created...");
      res.status(200).send({ message: "User Created" });
      // res.redirect("/app/");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send(err);
  }
});

module.exports = app;