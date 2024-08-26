import express from "express";
import con from "../utils/db.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import multer from "multer";
import path from "path";
import { verifyUser } from "../utils/authMiddleware.js";

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

router.post("/adminlogin", (req, res) => {
  const sql = "SELECT * FROM admin WHERE email = ?";

  con.query(sql, [req.body.email, req.body.password], (err, result) => {
    if (err) return res.json({ loginStatus: false, Error: "Query error" });
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
              role: "admin",
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

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ Status: true });
});

router.get("/admin_count", (req, res) => {
  const sql = "SELECT count(id) as admin FROM admin";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/currentAdmin", verifyUser, (req, res) => {
  const sql = "SELECT * FROM admin where id = ?";
  const userIdFromToken = req.userId;
  con.query(sql, [userIdFromToken], (err, result) => {
    if (err) return res.json({ Status: false, Error: err });
    return res.json({ Status: true, Result: result[0] });
  });
});

router.get("/admin/:id", (req, res) => {
  const sql = "SELECT email, isSuperAdmin FROM admin WHERE id = ?";
  con.query(sql, [req.params.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.put("/update_admin/:id", async (req, res) => {
  let sql = "UPDATE admin SET email = ?, isSuperAdmin = ?";
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
});

router.delete("/delete_admin/:id", (req, res) => {
  // Vérifiez si l'utilisateur est un super administrateur
  if (req.body.isSuperAdmin) {
    return res.json({
      Status: false,
      Error: "Impossible de supprimer un super Admin",
    });
  }

  // Commencez une transaction
  con.beginTransaction((err) => {
    if (err)
      return res.json({ Status: false, Error: "Transaction start error" });

    const sqlDeleteAdmin = "DELETE FROM admin WHERE id = ?";
    const sqlUpdateEmployee = "UPDATE employee SET isAdmin = ? WHERE email = ?";

    // Supprimez l'administrateur
    con.query(sqlDeleteAdmin, [req.params.id], (err, result) => {
      if (err) {
        return con.rollback(() => {
          res.json({ Status: false, Error: "Query error for deleting admin" });
        });
      }

      // Mettez à jour l'employé
      con.query(sqlUpdateEmployee, [0, req.body.email], (err, result) => {
        if (err) {
          return con.rollback(() => {
            res.json({
              Status: false,
              Error: "Query error for updating employee",
            });
          });
        }

        // Validez la transaction
        con.commit((err) => {
          if (err) {
            return con.rollback(() => {
              res.json({ Status: false, Error: "Transaction commit error" });
            });
          }

          // Transaction réussie
          res.json({ Status: true });
        });
      });
    });
  });
});

// router.delete("/delete_admin/:id", (req, res) => {
//   if (!req.body.isSuperAdmin) {
//     const sqlDeleteAdmin = "DELETE FROM admin WHERE id = (?)";
//     const sqlupdateEmployee = "UPDATE employee SET isAdmin = ? WHERE email = ?";

//     con.query(sqlDeleteAdmin, [req.params.id], (err, result) => {
//       if (err) return res.json({ Status: false, Error: "Query error" });
//       con.query(sqlupdateEmployee, [0, req.body.email], (err, result) => {
//         if (err) return res.json({ Status: false, Error: "Query error" });
//       });
//       return res.json({ Status: true });
//     });
//   } else {
//     return res.json({
//       Status: false,
//       Error: "Impossible de supprimer un super Admin",
//     });
//   }
// });

router.post("/add_admin", (req, res) => {
  // SQL TRANSACTION
  con.beginTransaction((err) => {
    if (err)
      return res.json({ Status: false, Error: "Transaction start error" });

    const sqlAddAdmin = "INSERT INTO admin (`email`, `password`) VALUES (?, ?)";
    const sqlUpdateEmployee = "UPDATE employee SET isAdmin = ? WHERE email = ?";

    con.query(
      sqlAddAdmin,
      [req.body.email, req.body.password],
      (err, result) => {
        if (err) {
          return con.rollback(() => {
            res.json({ Status: false, Error: "Query error for adding admin" });
          });
        }

        con.query(sqlUpdateEmployee, [1, req.body.email], (err, result) => {
          if (err) {
            return con.rollback(() => {
              res.json({
                Status: false,
                Error: "Query error for updating employee",
              });
            });
          }
          con.commit((err) => {
            if (err) {
              return con.rollback(() => {
                res.json({ Status: false, Error: "Transaction commit error" });
              });
            }

            res.json({
              Status: true,
              Message: "Admin added and employee updated",
            });
          });
        });
      }
    );
  });
});

// router.post("/add_admin", (req, res) => {
//   const sqlAddAdmin = "INSERT INTO admin (`email`, `password`) VALUES (?, ?)";
//   const sqlUpdateEmployee = "UPDATE employee SET isAdmin = ? WHERE email = ?";

//   con.query(sqlAddAdmin, [req.body.email, req.body.password], (err, result) => {
//     if (err) {
//       return res.json({
//         Status: false,
//         Error: "Query error during admin insertion",
//       });
//     }
//     con.query(sqlUpdateEmployee, [1, req.body.email], (err, result) => {
//       if (err) {
//         return res.json({
//           Status: false,
//           Error: "Query error during employee update",
//         });
//       }
//       return res.json({ Status: true });
//     });
//   });
// });

router.get("/admin_records", (req, res) => {
  const sql = "SELECT * FROM admin";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.post("/add_category", (req, res) => {
  /* @TODO: check if category already exists */
  const sql = "INSERT INTO category (`name`) VALUES (?)";
  con.query(sql, [req.body.category], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true });
  });
});

router.post("/update_category", (req, res) => {
  const sql = "UPDATE category SET name = (?) WHERE id = (?)";
  con.query(sql, [req.body.category, req.body.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true });
  });
});

router.post("/remove_category", (req, res) => {
  const sql = "DELETE FROM category WHERE id = (?)";
  con.query(sql, [req.body.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true });
  });
});

router.get("/category", (req, res) => {
  const sql = "SELECT * FROM category";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.post("/add_employee", upload.single("picture"), (req, res) => {
  /* @TODO: check if employee already exists */
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
      if (err) return res.json({ Status: false, Error: err });
      return res.json({ Status: true });
    });
  });
});

router.get("/employee", (req, res) => {
  const sql =
    "SELECT employee.*, category.name AS category_name from employee INNER JOIN category ON employee.category_id = category.id";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/employeesNoAdmin", (req, res) => {
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

router.get("/salary_count", (req, res) => {
  const sql = "SELECT sum(salary) as salary FROM employee";
  con.query(sql, (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.get("/employee/:id", (req, res) => {
  const sql = "SELECT * from employee WHERE id = (?)";
  con.query(sql, [req.params.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true, Result: result });
  });
});

router.put("/update_employee/:id", async (req, res) => {
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
  // Ajout de la condition WHERE pour l'ID
  sql += " WHERE id = ?";

  con.query(sql, [...values, req.params.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: err });
    return res.json({ Status: true });
  });
});

router.delete("/remove_employee/:id", (req, res) => {
  const sql = "DELETE FROM employee WHERE id = (?)";
  con.query(sql, [req.params.id], (err, result) => {
    if (err) return res.json({ Status: false, Error: "Query error" });
    return res.json({ Status: true });
  });
});

export { router as adminRouter };
