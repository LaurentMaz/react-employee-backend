import express from "express";
import con from "../utils/db.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import multer from "multer";
import path from "path";
import { verifyAdminRole, verifyUser } from "../utils/authMiddleware.js";

const router = express.Router();

// Image Upload System

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/images");
  },
  filename: (req, file, cb) => {
    const fileNameWithoutExt = path.basename(
      file.originalname,
      path.extname(file.originalname)
    );

    cb(
      null,
      fileNameWithoutExt + "_" + Date.now() + path.extname(file.originalname)
    );
  },
});

const upload = multer({
  storage: storage,
});
// End Image Upload System

// *************** //
// HANDLE ADMINS //
// *************** //

router.post("/adminlogin", (req, res) => {
  const sql = "SELECT * FROM employee WHERE email = ?";

  con.query(sql, [req.body.email, req.body.password], (err, result) => {
    if (err) return res.json({ loginStatus: false, Error: "Query error" });
    if (result.length > 0) {
      if (result[0].isAdmin) {
        bcrypt.compare(
          req.body.password,
          result[0].password,
          (err, response) => {
            if (err)
              return res.json({
                loginStatus: false,
                Error: "Bcrypt error",
              });
            if (response) {
              const email = result[0].email;
              const id = result[0].id;
              const token = jwt.sign(
                {
                  role: "admin",
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
          }
        );
      } else {
        return res.json({ loginStatus: false, Error: "Compte non autorisé" });
      }
    } else {
      return res.json({ loginStatus: false, Error: "Identifiants inconnus" });
    }
  });
});

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ Status: true });
});

router.get("/admin_count", (req, res) => {
  const sql = "SELECT count(id) as admin FROM employee WHERE isAdmin = ?";
  con.query(sql, [true], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/currentAdmin", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "SELECT * FROM employee where id = ? AND isAdmin = ?";
  const userIdFromToken = req.userId;
  con.query(sql, [userIdFromToken, true], (err, result) => {
    if (err) return res.json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result[0] });
  });
});

router.get("/admin/:id", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "SELECT email, isSuperAdmin FROM employee WHERE id = ?";
  con.query(sql, [req.params.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.put(
  "/update_admin/:id",
  verifyUser,
  verifyAdminRole,
  async (req, res) => {
    let sql = "UPDATE employee SET email = ?, isSuperAdmin = ?";
    const values = [req.body.email, req.body.adminChecked];

    // Si le mot de passe n'est pas vide, on l'ajoute à la requête
    if (req.body.password && req.body.password.trim() !== "") {
      const hash = await bcrypt.hash(req.body.password.toString(), 10);
      sql += ", password = ?";
      values.push(hash);
    }

    // Ajout de la condition WHERE pour l'ID
    sql += " WHERE id = ?";
    con.query(sql, [...values, req.params.id], (err, result) => {
      if (err) return res.json({ Status: false, Error: err });
      return res.json({ Status: true });
    });
  }
);

router.put("/delete_admin/:id", verifyUser, verifyAdminRole, (req, res) => {
  // Vérifiez si l'utilisateur est un super administrateur
  if (req.body.isSuperAdmin) {
    return res.json({
      Status: false,
      Error: "Impossible de supprimer un super Admin",
    });
  }
  const sql = "UPDATE employee SET isAdmin = ? WHERE id = ?";
  // Supprimez l'administrateur
  con.query(sql, [false, req.params.id], (err, result) => {
    if (err) {
      return con.rollback(() => {
        res.json({ Status: false, Error: "Query error for deleting admin" });
      });
    }
    // Transaction réussie
    res.json({ Status: true });
  });
});

router.put("/add_admin", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "UPDATE employee SET isAdmin = ? WHERE email = ?";

  con.query(sql, [true, req.body.email], (err, result) => {
    if (err) {
      return res.json({ Status: false, Error: err });
    }
    return res.json({ Status: true });
  });
});

router.get("/admin_records", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "SELECT * FROM employee WHERE isAdmin = ?";
  con.query(sql, [true], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

// *************** //
// HANDLE CATEGORIES //
// *************** //

router.post("/add_category", verifyUser, verifyAdminRole, (req, res) => {
  /* @TODO: check if category already exists */
  const sql = "INSERT INTO category (`name`) VALUES (?)";
  con.query(sql, [req.body.category], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true });
  });
});

router.put("/update_category", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "UPDATE category SET name = (?) WHERE id = (?)";
  con.query(sql, [req.body.category, req.body.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true });
  });
});

router.delete("/remove_category", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "DELETE FROM category WHERE id = (?)";
  con.query(sql, [req.params.id], (err, result) => {
    if (err) {
      // Vérifier le code d'erreur MySQL
      if (err.errno === 1451) {
        // Code 1451 : contrainte de clé étrangère (RESTRICT)
        return res.json({
          Status: false,
          ErrorMessage:
            "Impossible de supprimer cette catégorie car elle est référencée par d'autres éléments.",
        });
      }

      // Pour toute autre erreur, renvoyer l'erreur SQL générique ou un message d'erreur personnalisé
      return res.json({
        Status: false,
        ErrorMessage:
          "Une erreur s'est produite lors de la suppression de la catégorie.",
      });
    }

    return res.json({ Status: true });
  });
});

router.get("/category", verifyUser, (req, res) => {
  const sql = "SELECT * FROM category";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

// *************** //
// HANDLE EMPLOYEES //
// *************** //

router.post(
  "/add_employee",
  verifyUser,
  verifyAdminRole,
  upload.single("picture"),
  (req, res) => {
    /* @TODO: security checks */
    const sql =
      "INSERT INTO employee (`lastName`, `firstName`, `email`, `password`, `salary`, `address`, `category_id`, `picture`) VALUES (?)";
    bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
      if (err) return res.json({ Status: false, Error: "Query error" });
      const params = [
        req.body.lastName,
        req.body.firstName,
        req.body.email,
        hash,
        req.body.salary,
        req.body.address,
        req.body.category,
        req.file ? req.file.filename : "",
      ];
      con.query(sql, [params], (err, result) => {
        if (err) {
          // Vérifier le code d'erreur MySQL
          if (err.errno === 1062) {
            // Code 1451 : contrainte de clé étrangère (RESTRICT)
            return res.json({
              Status: false,
              ErrorMessage: "Un utilisateur existe déjà avec cet email",
            });
          }

          // Pour toute autre erreur, renvoyer l'erreur SQL générique ou un message d'erreur personnalisé
          return res.json({
            Status: false,
            ErrorMessage:
              "Une erreur s'est produite lors de l'ajout de l'utilisateur : " +
              err,
          });
        }
        return res.json({ Status: true });
      });
    });
  }
);

router.get("/employee", verifyUser, verifyAdminRole, (req, res) => {
  const sql =
    "SELECT employee.*, category.name AS category_name from employee LEFT JOIN category ON employee.category_id = category.id";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/searchEmployee", verifyUser, verifyAdminRole, (req, res) => {
  const searchValue = req.query.searchValue;
  let sql = "";
  if (searchValue !== "") {
    sql =
      "SELECT employee.*, category.name AS category_name  FROM employee LEFT JOIN category ON employee.category_id = category.id WHERE employee.firstName LIKE ? OR employee.lastName LIKE ? OR employee.email LIKE ?";
  } else {
    sql =
      "SELECT employee.*, category.name AS category_name  FROM employee LEFT JOIN category ON employee.category_id = category.id";
  }

  con.query(
    sql,
    [`%${searchValue}%`, `%${searchValue}%`, `%${searchValue}%`],
    (err, result) => {
      if (err) return res.json({ Status: false, Error: err });
      return res.json({ Status: true, Result: result });
    }
  );
});

router.get("/employeesNoAdmin", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "SELECT * from employee WHERE isAdmin = ? ORDER BY lastName ASC";
  con.query(sql, [0], (err, result) => {
    if (err) return res.json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/employee_count", (req, res) => {
  const sql = "SELECT count(id) as employee FROM employee";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/salary_count", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "SELECT sum(salary) as salary FROM employee";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/employee/:id", verifyUser, verifyAdminRole, (req, res) => {
  const sql = "SELECT * from employee WHERE id = (?)";
  con.query(sql, [req.params.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.put(
  "/update_employee/:id",
  verifyUser,
  verifyAdminRole,
  upload.single("picture"),
  async (req, res) => {
    const values = [
      req.body.firstName,
      req.body.lastName,
      req.body.email,
      req.body.salary,
      req.body.address,
      req.body.category,
    ];
    let sql =
      "UPDATE employee SET firstName = ?, lastName = ?,email = ?,salary = ?,address = ?,category_id = ?";

    // Si le mot de passe n'est pas vide, on l'ajoute à la requête
    if (req.body.password && req.body.password.trim() !== "") {
      const hash = await bcrypt.hash(req.body.password.toString(), 10);
      sql += ", password = ?";
      values.push(hash);
    }
    // Si l'image n'est pas vide, on l'ajoute à la requête
    if (req.file && req.file.filename.trim() !== "") {
      sql += ", picture = ?";
      values.push(req.file.filename);
    }

    // Ajout de la condition WHERE pour l'ID
    sql += " WHERE id = ?";

    con.query(sql, [...values, req.params.id], (err, result) => {
      if (err) return res.json({ Status: false, Error: err });
      return res.json({ Status: true });
    });
  }
);

router.delete(
  "/remove_employee/:id",
  verifyUser,
  verifyAdminRole,
  (req, res) => {
    const sql = "DELETE FROM employee WHERE id = (?)";
    con.query(sql, [req.params.id], (err, result) => {
      if (err) {
        // Vérifier le code d'erreur MySQL
        if (err.errno === 1451) {
          // Code 1451 : contrainte de clé étrangère (RESTRICT)
          return res.json({
            Status: false,
            ErrorMessage:
              "Impossible de supprimer cet utilisateur, un équipement lui est encore attribué",
          });
        }

        // Pour toute autre erreur, renvoyer l'erreur SQL générique ou un message d'erreur personnalisé
        return res.json({
          Status: false,
          ErrorMessage:
            "Une erreur s'est produite lors de la suppression de la catégorie.",
        });
      }

      return res.json({ Status: true });
    });
  }
);

// *************** //
// HANDLE EQUIPEMENTS //
// *************** //

router.get("/equipements", verifyUser, verifyAdminRole, (req, res) => {
  const sql =
    "SELECT equipement.*, DATE_FORMAT(equipement.date_service, '%d/%m/%Y') AS date_service , employee.id AS employee_id, CONCAT(employee.firstName, ' ', employee.lastName) AS employee_name FROM equipement LEFT JOIN employee ON equipement.employee_id = employee.id";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/equipements/:id", verifyUser, verifyAdminRole, (req, res) => {
  const sql =
    "SELECT equipement.*, employee.id AS employee_id FROM equipement LEFT JOIN employee ON equipement.employee_id = employee.id WHERE equipement.id = (?)";
  con.query(sql, [req.params.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: err });

    // Extraire et formater la date
    const formattedResult = result.map((item) => {
      const date = new Date(item.date_service); // Création d'un objet Date
      const formattedDate = date.toISOString().split("T")[0]; // Formatage au format YYYY-MM-DD
      return {
        ...item, // Conserver les autres propriétés de l'objet
        date_service: formattedDate, // Remplacer la date avec le format correct
      };
    });

    return res.json({ Status: true, Result: formattedResult });
  });
});

router.post("/add_equipement", verifyUser, verifyAdminRole, (req, res) => {
  const sql =
    "INSERT INTO equipement (`brand`, `name`, `ram`, `proc`, `serial`, `date_service`, `employee_id`) VALUES (?)";
  const params = [
    req.body.brand,
    req.body.name,
    req.body.ram,
    req.body.proc,
    req.body.serial,
    req.body.date_service,
    req.body.employee_id,
  ];
  con.query(sql, [params], (err, result) => {
    if (err) return res.json({ Status: false, Error: err });
    return res.json({ Status: true });
  });
});

router.put("/update_equipement", verifyUser, verifyAdminRole, (req, res) => {
  const sql = `
  UPDATE equipement
  SET brand = ?, name = ?, serial = ?, employee_id = ?, ram = ?, proc = ?
  WHERE id = ?;
`;
  const { equipement, id } = req.body;
  if (!equipement || !id) {
    return res.status(400).json({ Status: false, Error: "Missing parameters" });
  }
  con.query(
    sql,
    [
      equipement.brand,
      equipement.name,
      equipement.serial,
      equipement.employee_id,
      equipement.ram,
      equipement.proc,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Status: false, Error: err });
      return res.json({ Status: true });
    }
  );
});

router.delete(
  "/remove_equipement/",
  verifyUser,
  verifyAdminRole,
  (req, res) => {
    const sql = "DELETE FROM equipement WHERE id = (?)";
    con.query(sql, [req.body.id], (err, result) => {
      if (err) return res.json({ Status: false, Error: err });
      return res.json({ Status: true });
    });
  }
);

router.get("/searchEquipement", verifyUser, verifyAdminRole, (req, res) => {
  const searchValue = req.query.searchValue;
  let sql = "";
  if (searchValue !== "") {
    sql =
      "SELECT equipement.*, DATE_FORMAT(equipement.date_service, '%d/%m/%Y') AS date_service , employee.id AS employee_id, employee.firstName, employee.lastName, CONCAT(employee.firstName, ' ', employee.lastName) AS employee_name FROM equipement LEFT JOIN employee ON equipement.employee_id = employee.id WHERE equipement.name LIKE ? OR equipement.brand LIKE ? OR employee.firstName LIKE ? OR employee.lastName LIKE ?";
  } else {
    sql =
      "SELECT equipement.*, DATE_FORMAT(equipement.date_service, '%d/%m/%Y') AS date_service , employee.id AS employee_id, CONCAT(employee.firstName, ' ', employee.lastName) AS employee_name FROM equipement LEFT JOIN employee ON equipement.employee_id = employee.id";
  }

  con.query(
    sql,
    [
      `%${searchValue}%`,
      `%${searchValue}%`,
      `%${searchValue}%`,
      `%${searchValue}%`,
    ],
    (err, result) => {
      if (err) return res.json({ Status: false, Error: err });
      return res.json({ Status: true, Result: result });
    }
  );
});

export { router as adminRouter };
