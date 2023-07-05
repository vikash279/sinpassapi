const express = require('express');
const route = express.Router();
const axios = require('axios');

const mainController = require("../controller/mainController");

route.get("/check",mainController.apiCheck)
route.post("/getprofile",mainController.getProfile)



route.all("/*", function (req, res) {
    res.status(400).send({status: false,message: "The api you request is not available"})
})
module.exports = route;