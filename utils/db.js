import mysql from "mysql";

const con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "employeems",
});

con.connect(function (err) {
  if (err) {
    console.log("Connexion error:", err);
  } else {
    console.log("Connected to DB");
  }
});

export default con;
