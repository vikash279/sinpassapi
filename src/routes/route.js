const express = require('express');
const route = express.Router();
const axios = require('axios');

const mainController = require("../controller/mainController");

route.get("/",mainController.apiIndex)
route.get("/check",mainController.apiCheck)
route.post("/getprofile",mainController.getProfile)
route.get("/getenv",mainController.getEnv)
route.post("/authorize",mainController.authorize)
route.post("/getaccesstoken",mainController.getAccessToken)
route.post("/getpersondata",mainController.getPersonData)



route.all("/*", function (req, res) {
    res.status(400).send({status: false,message: "The api you request is not available"})
})
module.exports = route;