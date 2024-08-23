import express from "express";
import cors from "cors";
import { adminRouter } from "./Routes/AdminRoute.js";
import { employeeRouter } from "./Routes/EmployeeRoute.js";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const app = express();
app.use(
  cors({
    origin: ["http://localhost:5173"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use("/auth", adminRouter);
app.use("/employee", employeeRouter);
app.use(express.static("public"));

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  console.log("Token from cookies: ", token); // Debugging
  if (!token) return res.json({ Status: false, Error: "Non authentifié" });
  if (token) {
    jwt.verify(token, "jwt_secret_key", (err, decoded) => {
      if (err) return res.json({ Status: false, Error: "Wrong token" });
      req.id = decoded.id;
      req.role = decoded.role;
      next();
    });
  }
};
app.get("/verifyLogin", verifyUser, (req, res) => {
  return res.json({ Status: true, role: req.role, id: req.id });
});

app.listen(3000, () => {
  console.log("Server running...");
});
