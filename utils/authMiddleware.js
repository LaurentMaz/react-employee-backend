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
    });
  }
  next();
};

export const verifyIdIntegrity = (req, res, next) => {
  const role = req.role;
  const userIdFromToken = req.userId; // ID récupéré du token après authentification
  if (role !== "admin") {
    if (userIdFromToken.toString() !== req.params.id.toString()) {
      return res.json({ Status: false, Error: "Non autorisé" });
    }
  }
  next();
};
