const mysql = require("mysql");
//connect to mysql
var connect = mysql.createConnection({
  host: "localhost",
  user: "nerojust",
  password: "Matthew123@",
  database: "NodeJS_DB"
});
connect.connect();

module.exports = connect;
