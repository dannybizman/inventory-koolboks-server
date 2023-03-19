const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");



const app = express();


const PORT = process.env.PORT || 5000;

// connect to D and Start server

mongoose
.connect(process.env.MONGO_URI,{useNewUrlParser: true,useUnifiedTopology: true})
.then(() => {
app.listen(PORT, () => {
    console.log(`Server Running on port ${PORT}`);
});

})

.catch((err) =>console.log(err))