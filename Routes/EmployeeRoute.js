import express from "express";
import con from "../utils/db.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const router = express.Router();

// Middleware
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token)
    return res.status(401).json({ Status: false, Error: "Non authentifié" });

  jwt.verify(token, "jwt_secret_key", (err, decoded) => {
    if (err)
      return res.status(403).json({ Status: false, Error: "Token invalide" });
    req.userId = decoded.id; // L'utilisateur authentifié
    next();
  });
};

router.post("/employeelogin", (req, res) => {
  const sql = "SELECT id, email, password FROM employee WHERE email = ?";
  con.query(sql, [req.body.email], (err, result) => {
    if (err) return res.json({ loginStatus: false, Error: err });
    if (result.length > 0) {
      bcrypt.compare(req.body.password, result[0].password, (err, response) => {
        if (err)
          return res.json({
            loginStatus: false,
            Error: "Mauvais mot de passe",
          });
        if (response) {
          const email = result[0].email;
          const id = result[0].id;
          const token = jwt.sign(
            {
              role: "employee",
              email: email,
              id: id,
            },
            "jwt_secret_key", // ADD TO ENV SECRET KEY !!
            { expiresIn: "1d" }
          );
          res.cookie("token", token);
          return res.json({ loginStatus: true, id: result[0].id });
        }
      });
    } else {
      return res.json({ loginStatus: false, Error: "Identifiants inconnus" });
    }
  });
});

router.get("/detail/:id", verifyUser, (req, res) => {
  const userIdFromToken = req.userId; // ID récupéré du token après authentification
  const userIdFromParams = parseInt(req.params.id, 10); // ID dans l'URL

  // Vérifiez si l'utilisateur authentifié tente d'accéder à ses propres données
  if (userIdFromToken !== userIdFromParams) {
    return res.json({ Status: false, Error: "Accès interdit" });
  }

  const sql = "SELECT * FROM employee WHERE id = ?";
  con.query(sql, [req.params.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result[0] });
  });
});

router.get("/detail", verifyUser, (req, res) => {
  const userIdFromToken = req.userId; // ID récupéré du token après authentification

  const sql = "SELECT * FROM employee WHERE id = ?";
  con.query(sql, [userIdFromToken], (err, result) => {
    if (err) return res.json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result[0] });
  });
});

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ Status: true });
});

export { router as employeeRouter };
