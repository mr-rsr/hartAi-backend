var mysql = require('mysql2');
var conn = mysql.createConnection({
  host: 'localhost', // Replace with your host name
  user: 'mr-rsr',      // Replace with your database username
  password: 'Mrrsr@01',      // Replace with your database password
  database: 'hartai' // // Replace with your database Name
}); 

conn.connect(function(err) {
  if (err) throw err;
  console.log('Database is connected successfully !');
});
module.exports =conn;