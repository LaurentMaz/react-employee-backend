import express from "express";
import pool from "../utils/db.js";
const con = pool;
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

// export function fizzBuzz(n) {
//   if (n % 3 === 0 && n % 5 === 0) return "FizzBuzz";
//   if (n % 3 === 0) return "Fizz";
//   if (n % 5 === 0) return "Buzz";
//   return n.toString();
// }

// Fonction pour vérifier si un jour est un jour ouvrable (lundi-vendredi)
function isBusinessDay(date) {
  const dayOfWeek = date.isoWeekday(); // 1 (lundi) à 5 (vendredi)
  return dayOfWeek >= 1 && dayOfWeek <= 5;
}

// Fonction pour calculer les jours ouvrables entre deux dates
export function countBusinessDays(startDate, endDate) {
  let count = 0;
  let currentDate = moment(startDate); // Crée un clone pour ne pas modifier l'original

  // Itérer sur chaque jour entre startDate et endDate
  while (currentDate.isSameOrBefore(endDate, "day")) {
    if (isBusinessDay(currentDate)) {
      if (currentDate.isoWeekday() === 5) {
        // Si c'est vendredi
        count += 2; // Ajouter 2 jours
      } else {
        count++; // Sinon, ajouter 1 jour
      }
    }
    currentDate.add(1, "day"); // Passe au jour suivant
  }

  return count;
}

// Fonction pour récupérer les infos d'un congé depuis son id
async function getCongeById(id) {
  return new Promise((resolve, reject) => {
    const sql = "SELECT * FROM conges WHERE id = ?";

    con.query(sql, [id], (err, result) => {
      if (err) {
        return reject(err);
      }
      if (result.length === 0) {
        return resolve(null);
      }
      return resolve(result[0]);
    });
  });
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
            { expiresIn: "2h" }
          );
          res.cookie("token", token, {
            httpOnly: true,
          });
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
  const sql =
    "SELECT id,status, DATE_FORMAT(startDate, '%d/%m/%Y') AS startDate, DATE_FORMAT(endDate, '%d/%m/%Y') AS endDate, reason, businessDays from conges WHERE employeeId = ?";
  con.query(sql, [userIdFromToken], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/conge/:id", verifyUser, verifyEmployeeRole, (req, res) => {
  const userIdFromToken = req.userId;
  const sql =
    "SELECT *, DATE_FORMAT(startDate, '%Y-%m-%d') as startDate, DATE_FORMAT(endDate, '%Y-%m-%d') as endDate FROM conges WHERE id = ?AND employeeId = ?";
  con.query(sql, [req.params.id, userIdFromToken], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/conges_pending", verifyUser, verifyEmployeeRole, (req, res) => {
  const userIdFromToken = req.userId;
  const sql =
    "SELECT id,status, DATE_FORMAT(startDate, '%d/%m/%Y') AS startDate, DATE_FORMAT(endDate, '%d/%m/%Y') AS endDate, reason, businessDays from conges WHERE employeeId = ? AND status = ?";
  con.query(sql, [userIdFromToken, "En cours"], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/conges_accepted", verifyUser, verifyEmployeeRole, (req, res) => {
  const userIdFromToken = req.userId;
  const sql =
    "SELECT id,status, DATE_FORMAT(startDate, '%d/%m/%Y') AS startDate, DATE_FORMAT(endDate, '%d/%m/%Y') AS endDate, reason, businessDays from conges WHERE employeeId = ? AND status = ?";
  con.query(sql, [userIdFromToken, "Approuvé"], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/conges_refused", verifyUser, verifyEmployeeRole, (req, res) => {
  const userIdFromToken = req.userId;
  const sql =
    "SELECT id,status, DATE_FORMAT(startDate, '%d/%m/%Y') AS startDate, DATE_FORMAT(endDate, '%d/%m/%Y') AS endDate, reason, businessDays from conges WHERE employeeId = ? AND status = ?";
  con.query(sql, [userIdFromToken, "Rejeté"], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

router.get(
  "/congesAvalaible_currentYear",
  verifyUser,
  verifyEmployeeRole,
  (req, res) => {
    const userIdFromToken = req.userId;
    const sql = `SELECT SUM(businessDays) AS totalBusinessDays
FROM conges
WHERE startDate >= STR_TO_DATE(CONCAT(YEAR(CURDATE()) - 1, '-06-01'), '%Y-%m-%d')
AND endDate <= STR_TO_DATE(CONCAT(YEAR(CURDATE()), '-05-31'), '%Y-%m-%d') AND employeeId = ? AND status = ?;
`;
    con.query(sql, [userIdFromToken, "Approuvé"], (err, result) => {
      if (err) return res.status(500).json({ Status: false, Error: err });
      return res.json({ Status: true, Result: result });
    });
  }
);

router.get(
  "/congesAvalaible_nextYear",
  verifyUser,
  verifyEmployeeRole,
  (req, res) => {
    const userIdFromToken = req.userId;
    const sql = `SELECT SUM(businessDays) AS totalBusinessDays
FROM conges
WHERE startDate >= STR_TO_DATE(CONCAT(YEAR(CURDATE()), '-06-01'), '%Y-%m-%d')
AND endDate <= STR_TO_DATE(CONCAT(YEAR(CURDATE()) +1, '-05-31'), '%Y-%m-%d') AND employeeId = ? AND status = ?;
`;
    con.query(sql, [userIdFromToken, "Approuvé"], (err, result) => {
      if (err) return res.status(500).json({ Status: false, Error: err });
      return res.json({ Status: true, Result: result });
    });
  }
);

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

router.put("/update_conge", verifyUser, verifyEmployeeRole, (req, res) => {
  const userIdFromToken = req.userId;
  const startDate = moment(req.body.startDate); // Date de début
  const endDate = moment(req.body.endDate); // Date de fin
  const businessDays = countBusinessDays(startDate, endDate);

  const sql =
    "UPDATE conges SET id = ?, employeeId = ?,congeTypesId = ?,startDate = ?,endDate = ?,status = ?, reason=?,businessDays=? WHERE id = ?";

  const params = [
    req.body.id,
    userIdFromToken,
    req.body.congeTypesId,
    req.body.startDate,
    req.body.endDate,
    "En cours",
    req.body.reason,
    businessDays,
    req.body.id,
  ];

  con.query(sql, params, (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true });
  });
});

router.delete(
  "/remove_conge/:id",
  verifyUser,
  verifyEmployeeRole,
  async (req, res) => {
    const userIdFromToken = req.userId;
    const congeId = parseInt(req.params.id);
    const conge = await getCongeById(congeId);

    if (conge.employeeId !== userIdFromToken) {
      return res
        .status(403)
        .json({ Status: false, Error: "Accès non autorisé" });
    }

    const sql = "DELETE FROM conges WHERE id = (?)";
    con.query(sql, [req.params.id], (err, result) => {
      if (err) {
        return res.json({
          Status: false,
          ErrorMessage:
            "Une erreur s'est produite lors de la suppression du congé.",
        });
      }

      return res.json({ Status: true });
    });
  }
);

// *************** //
// HANDLE TICKETS //
// *************** //

router.post("/add_ticket", verifyUser, (req, res) => {
  const userIdFromToken = req.userId;

  const sql =
    "INSERT INTO tickets (`titre`, `details`, `service`, `statut`, `id_machine`, `id_employee`, `urgence`, `emp_related`) VALUES (?)";
  const params = [
    req.body.title,
    req.body.details,
    req.body.service,
    req.body.status,
    req.body.id_machine,
    userIdFromToken,
    req.body.urgence,
    req.body.emp_related,
  ];
  con.query(sql, [params], (err, result) => {
    if (err) return res.status(500).json({ Status: false, Error: err });
    return res.json({ Status: true });
  });
});

export { router as employeeRouter };
