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
  const sql = "SELECT * FROM admin WHERE email = ? AND password = ?";

  con.query(sql, [req.body.email, req.body.password], (err, result) => {
    if (err) return res.json({ loginStatus: false, Error: "Query error" });
    if (result.length > 0) {
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
      return res.json({ loginStatus: true });
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

router.put("/update_admin/:id", (req, res) => {
  const sql = "UPDATE admin SET email = ?, isSuperAdmin = ? WHERE id = ?";
  con.query(
    sql,
    [req.body.email, req.body.adminChecked, req.params.id],
    (err, result) => {
      if (err) return res.json({ Status: false, Error: err });
      return res.json({ Status: true });
    }
  );
});

router.delete("/delete_admin/:id", (req, res) => {
  if (!req.body.isSuperAdmin) {
    const sql = "DELETE FROM admin WHERE id = (?)";
    con.query(sql, [req.params.id], (err, result) => {
      if (err) return res.json({ Status: false, Error: "Query error" });
      return res.json({ Status: true });
    });
  }
  return res.json({
    Status: false,
    Error: "Impossible de supprimer un super Admin",
  });
});

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

router.put("/update_employee/:id", (req, res) => {
  const values = [
    req.body.firstName,
    req.body.lastName,
    req.body.email,
    req.body.salary,
    req.body.address,
    req.body.category,
  ];
  const sql =
    "UPDATE employee SET firstName = ?, lastName = ?,email = ?,salary = ?,address = ?,category_id = ? WHERE id = ?";
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
