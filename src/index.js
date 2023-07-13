const express = require('express');
const route =require("./routes/route.js");
const cors = require("cors");
var bodyParser = require("body-parser");
var cookieParser = require("cookie-parser");

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);
app.use(cookieParser());
app.use(express.json()); 
app.use('/', route);


const port = 3001;
app.listen(port, function () {
    console.log('Express app running on port ' + port);
});