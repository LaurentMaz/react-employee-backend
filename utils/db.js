import mysql from "mysql";

// const con = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "",
//   database: "employees",
// });

// con.connect(function (err) {
//   if (err) {
//     console.log("Connexion error:", err);
//   } else {
//     console.log("Connected to DB");
//   }
// });

const pool = mysql.createPool({
  connectionLimit: 50,
  host: "localhost",
  user: "root",
  password: "",
  database: "employees",
});

pool.getConnection(function (err, connection) {
  if (err) {
    console.log("Connexion error:", err);
  } else {
    console.log("Connected to DB");
  }
  connection.release();
});

// export default con;
export default pool;
