const express = require('express');
const router = express.Router();
const db  = require('./dbConnection');
const { signupValidation, loginValidation } = require('./validation');
const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

router.post('/register', signupValidation, (req, res, next) => {
    


    
    const email = req.body.email.toLowerCase();
    
    db.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER(?)',
      [email],
      async (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).send({ msg: 'Internal Server Error' });
        }
    
        try {
          if (result && result.length) {
            return res.status(409).send({ msg: 'This user is already in use!' });
          }
    
          const hash = await bcrypt.hash(req.body.password, 10);
    
          await db.query(
            'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
            [req.body.name, email, hash]
          );
    
          return res.status(201).send({ msg: 'The user has been registered with us!' });
        } catch (err) {
          console.error(err);
          return res.status(500).send({ msg: 'Internal Server Error' });
        }
      }
    );
    
});


router.post('/login', loginValidation, (req, res, next) => {
  db.query(
    `SELECT * FROM users WHERE email = ${escape(req.body.email)};`,
    (err, result) => {
      // user does not exists
      if (err) {
        throw err;
        return res.status(400).send({
          msg: err
        });
      }
      if (!result.length) {
        return res.status(401).send({
          msg: 'Email or password is incorrect!'
        });
      }
      // check password
      compare(
        req.body.password,
        result[0]['password'],
        (bErr, bResult) => {
          // wrong password
          if (bErr) {
            throw bErr;
            return res.status(401).send({
              msg: 'Email or password is incorrect!'
            });
          }
          if (bResult) {
            const token = sign({id:result[0].id},'the-super-strong-secrect',{ expiresIn: '1h' });
            db.query(
              `UPDATE users SET last_login = now() WHERE id = '${result[0].id}'`
            );
            return res.status(200).send({
              msg: 'Logged in!',
              token,
              user: result[0]
            });
          }
          return res.status(401).send({
            msg: 'Username or password is incorrect!'
          });
        }
      );
    }
  );
});

router.post('/get-user', signupValidation, (req, res, next) => {


    if(
        !req.headers.authorization ||
        !req.headers.authorization.startsWith('Bearer') ||
        !req.headers.authorization.split(' ')[1]
    ){
        return res.status(422).json({
            message: "Please provide the token",
        });
    }

    const theToken = req.headers.authorization.split(' ')[1];
    const decoded = verify(theToken, 'the-super-strong-secrect');

    db.query('SELECT * FROM users where id=?', decoded.id, function (error, results, fields) {
        if (error) throw error;
        return res.send({ error: false, data: results[0], message: 'Fetch Successfully.' });
    });


});


module.exports= router;