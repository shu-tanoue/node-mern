require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");

const userRoute = require("./routes/user.route");

//setup express
const app = express();
app.use(bodyParser.json({ extended: false }));

//route
app.use("/users", userRoute);

//connect the server
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => console.log(`The server has started on port: ${PORT}`));

//set up mongoose
mongoose.connect(
  process.env.MONGODB_URL,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
  },
  err => {
    if (err) throw err;
    console.log("Connected to Database!");
  }
);
