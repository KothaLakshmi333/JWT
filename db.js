const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');


const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  password: "" ,
  database: "nodedb"
});

app.get('/users', (req, res) => {
    const sql = "SELECT id, name, email FROM users";
    db.query(sql, (err, data) => {
        if (err) {
            return res.json("Error");
        }
        return res.json(data);
    });
});

app.post('/signup', async (req, res) => {
    const checkEmailSql = "SELECT * FROM users WHERE email = ?";
    const insertUserSql = "INSERT INTO users(`name`,`email`,`password`) VALUES(?)";

    try {
        db.query(checkEmailSql, [req.body.email], async (err, data) => {
            if (err) {
                return res.status(500).json("Error");
            }
            
            if (data.length > 0) {
                return res.status(400).json("Email already exists");
            }

            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            const values = [
                req.body.name,
                req.body.email,
                hashedPassword,
            ];

            db.query(insertUserSql, [values], (err, data) => {
                if (err) {
                    return res.status(500).json("Error");
                }
                return res.status(201).json("User created successfully");
            });
        });
    } catch (error) {
        res.status(500).json("Internal Server Error");
    }
});


app.post('/login', (req, res) => {
    const sql = "SELECT * FROM users WHERE `email` = ?";

    db.query(sql, [req.body.email], async (err, data) => {
        if (err) {
            return res.json("Error");
        }
        if (data.length > 0) {
            const validPassword = await bcrypt.compare(req.body.password, data[0].password);
            if (validPassword) {
                const id = data[0].id;
                const token = jwt.sign({ id }, "jwtSecretKey", { expiresIn: 30});
                return res.json({ Login: true , message:"login successful", token, data });
            } else {
                return res.json("Invalid password");
            }
        } else {
            return res.json("User not found");
        }
    });
});

app.listen(8080, () => {
    console.log("listening");
});
