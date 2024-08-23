import express from "express";
import cors from "cors";
import { adminRouter } from "./Routes/AdminRoute.js";
import { employeeRouter } from "./Routes/EmployeeRoute.js";

const app = express();
app.use(
  cors({
    origin: ["http://localhost:5173"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(express.json());
app.use("/auth", adminRouter);
app.use("/employee", employeeRouter);
app.use(express.static("public"));

app.listen(3000, () => {
  console.log("Server running...");
});
