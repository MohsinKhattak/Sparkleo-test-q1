const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const SECRET_KEY = "mohsin";

const userObj = {
  id: 1,
  email: "khattakcodes@gmail.com",
  password: bcrypt.hashSync("password", 8),
};

app.use(bodyParser.json());

app.get("/check", (req, res) => {
  res.status(200).send({ message: "No Issue" });
});

//login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (email !== userObj.email) {
    return res.status(404).send({ message: "User is not found" });
  }

  const checkPassword = bcrypt.compareSync(password, userObj.password);

  if (!checkPassword) {
    return res.status(401).send({ token: null, message: "Invalid password" });
  }

  const token = jwt.sign({ id: userObj.id, email: userObj.email }, SECRET_KEY, {
    expiresIn: 3600 * 24,
  });

  res.status(200).send({ token });
});

//middleware
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).send({ message: "No token provided" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(500).send({ message: "Failed to authenticate token" });
    }
    req.userId = decoded.id;
    req.userEmail = decoded.email;
    next();
  });
}

//protected Route
app.get("/protected", verifyToken, (req, res) => {
  res.status(200).send({
    message: `Hurray ${req.userEmail}, you did it`,
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
