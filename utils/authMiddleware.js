import jwt from "jsonwebtoken";

//Middleware
export const verifyUser = (req, res, next) => {
  const token = req.cookies.token; // Debugging
  if (!token) return res.json({ Status: false, Error: "Non authentifié" });
  if (token) {
    jwt.verify(token, "jwt_secret_key", (err, decoded) => {
      if (err) return res.json({ Status: false, Error: "Wrong token" });
      req.userId = decoded.id;
      req.role = decoded.role;
      next();
    });
  }
};
