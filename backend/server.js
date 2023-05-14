const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const userRoute = require("./routes/userRoute");
const errorHandler = require("./middleWare/errorMiddleware");
const cookieParser = require("cookie-parser");

const app = express();

//Middlewares

app.use(express.json())
app.use(cookieParser())
app.use(express.urlencoded({ extended: false}))
app.use(bodyParser.json())

//Routes Middleware
app.use("/api/users", userRoute);


//routes
app.get('/', (req, res) => {
    res.send("Home Page");
});

//Error Middleware
app.use(errorHandler);


// connect to DB and Start server
const PORT = process.env.PORT || 5000;

mongoose
.connect(process.env.MONGO_URI,{useNewUrlParser: true,useUnifiedTopology: true})
.then(() => {
app.listen(PORT, () => {
    console.log(`Server Running on port ${PORT}`);
});

})

.catch((err) =>console.log(err))