import express from "express";
import con from "../utils/db.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import {
  verifyEmployeeRole,
  verifyIdIntegrity,
  verifyUser,
} from "../utils/authMiddleware.js";
import moment from "moment";

const router = express.Router();

/**
 * FUNCTIONS GLOBALES
 */

// Fonction pour vérifier si un jour est un jour ouvrable (lundi-vendredi)
function isBusinessDay(date) {
  const dayOfWeek = date.isoWeekday(); // 1 (lundi) à 5 (vendredi)
  return dayOfWeek >= 1 && dayOfWeek <= 6;
}

// Fonction pour calculer les jours ouvrables entre deux dates
function countBusinessDays(startDate, endDate) {
  let count = 0;
  let currentDate = moment(startDate); // Crée un clone pour ne pas modifier l'original

  // Itérer sur chaque jour entre startDate et endDate
  while (currentDate.isSameOrBefore(endDate, "day")) {
    if (isBusinessDay(currentDate)) {
      count++;
    }
    currentDate.add(1, "day"); // Passe au jour suivant
  }

  return count;
}

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
        } else {
          return res.json({
            loginStatus: false,
            Error: "Mot de passe invalide",
          });
        }
      });
    } else {
      return res.json({ loginStatus: false, Error: "Identifiants inconnus" });
    }
  });
});

router.get("/detail", verifyUser, verifyEmployeeRole, (req, res) => {
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

// *************** //
// HANDLE EQUIPEMENTS //
// *************** //

router.get("/equipements/", verifyUser, verifyEmployeeRole, (req, res) => {
  const userIdFromToken = req.userId;

  const sql = "SELECT * from equipement WHERE employee_id = ?";
  con.query(sql, [userIdFromToken], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

// *************** //
// HANDLE CONGES //
// *************** //

router.get("/conge_types", (req, res) => {
  const sql = "SELECT * from congeTypes";
  con.query(sql, (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/conges", verifyUser, verifyEmployeeRole, (req, res) => {
  const userIdFromToken = req.userId;
  const sql = "SELECT * from conges WHERE employeeId = ?";
  con.query(sql, [userIdFromToken], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true });
  });
});

router.post("/add_conge", verifyUser, (req, res) => {
  const userIdFromToken = req.userId;
  const startDate = moment(req.body.startDate); // Date de début
  const endDate = moment(req.body.endDate); // Date de fin
  const businessDays = countBusinessDays(startDate, endDate);

  const sql =
    "INSERT INTO conges (`employeeId`, `congeTypesId`, `startDate`, `endDate`, `reason`, `businessDays`) VALUES (?)";
  const params = [
    userIdFromToken,
    req.body.congeTypesId,
    req.body.startDate,
    req.body.endDate,
    req.body.reason,
    businessDays,
  ];
  con.query(sql, [params], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true });
  });
});

export { router as employeeRouter };
