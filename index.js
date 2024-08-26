import express from "express";
import cors from "cors";
import { adminRouter } from "./Routes/AdminRoute.js";
import { employeeRouter } from "./Routes/EmployeeRoute.js";
import cookieParser from "cookie-parser";
import { verifyUser } from "./utils/authMiddleware.js";

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

app.get("/verifyLogin", verifyUser, (req, res) => {
  return res.json({ Status: true, role: req.role, id: req.id });
});

app.listen(3000, () => {
  console.log("Server running...");
});
