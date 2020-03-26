const mysql = require("mysql");
//connect to mysql
var connect = mysql.createConnection(
  {
    host: "localhost",
    user: "root",
    password: "Matthew123@.",
    database: "NodeJS_DB"
  },
  (err, result) => {
    if (err) {
      console.log(err);
    }
  }
);
connect.connect();

module.exports = connect;
