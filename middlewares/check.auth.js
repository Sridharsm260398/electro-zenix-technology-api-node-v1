const jwt = require("jsonwebtoken");

module.exports.authMiddleware  = async (req, res, next) => {
  try {
    //console.log(req.headers.authorization)
    const token = req.headers.authorization.split(" ")[1];
    console.log(token)
    console.log(process.env.JWT_SECRET_KEY)
    const data = await jwt.verify(token,  process.env.JWT_SECRET_KEY)
    console.log(`'User Id':${data.userID}`)
    next();
  } catch (error) {
    res.status(401).json({ message: "Auth failed!" });
  }
};
