const express = require('express')
var cors = require('cors')
const app = express()
const port = 8080
app.use(cors());
app.use("/", express.static("./"));
app.listen(port, () => console.log(`Example app listening on port ${port}!`))