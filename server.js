const express = require("express");
const dotenv = require("dotenv");
const app = express();
var cors =require("cors");
require("./conn");
const router = require("./routes/router");
dotenv.config();
app.use(express.json());
app.use(cors());
app.use(router);

app.listen(process.env.PORT, () => {
    console.log("Server listening at port" + process.env.PORT);
});
