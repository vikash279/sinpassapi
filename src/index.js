const express = require('express');
const route =require("./routes/route.js");

const app = express();

app.use(express.json()); 
app.use('/', route);

const port = 3000;
app.listen(port, function () {
    console.log('Express app running on port ' + port);
});