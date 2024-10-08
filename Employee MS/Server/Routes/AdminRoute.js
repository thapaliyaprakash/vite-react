import express from "express";
import con from "../utils/db.js";
import jwt from "jsonwebtoken";
import bcrypt from 'bcrypt';
import multer from "multer";
import path from "path";

const router = express.Router();

// Admin Login Route
router.post("/adminlogin", (req, res) => {
  const sql = "SELECT * FROM admin WHERE email = ?";
  con.query(sql, [req.body.email], (err, result) => {
    if (err) return res.json({ loginStatus: false, Error: "Query error" });
    
    if (result.length > 0) {
      const admin = result[0];
      bcrypt.compare(req.body.password, admin.password, (err, match) => {
        if (err) return res.json({ loginStatus: false, Error: "Error comparing passwords" });
        
        if (match) {
          const token = jwt.sign(
            { role: "admin", email: admin.email, id: admin.id },
            "jwt_secret_key",
            { expiresIn: "1d" }
          );
          res.cookie('token', token);
          return res.json({ loginStatus: true });
        } else {
          return res.json({ loginStatus: false, Error: "Wrong email or password" });
        }
      });
    } else {
      return res.json({ loginStatus: false, Error: "Admin not found" });
    }
  });
});

// Get Categories
router.get('/category', (req, res) => {
    const sql = "SELECT * FROM category";
    con.query(sql, (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" });
        return res.json({ Status: true, Result: result });
    });
});

// Add Category
router.post('/add_category', (req, res) => {
    const sql = "INSERT INTO category (name) VALUES (?)";
    con.query(sql, [req.body.category], (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" });
        return res.json({ Status: true });
    });
});

// Image Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'Public/Images');
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// Add Employee Route
router.post('/add_employee', upload.single('image'), (req, res) => {
    // Check if file was uploaded
    if (!req.file) {
        return res.json({ Status: false, Error: "Image file is required" });
    }
    
    const sql = `INSERT INTO employee 
                 (name, email, password, address, salary, image, category_id) 
                 VALUES (?)`;

    bcrypt.hash(req.body.password, 10, (err, hash) => {
        if (err) return res.json({ Status: false, Error: "Error hashing password" });
        
        const values = [
            req.body.name,
            req.body.email,
            hash,
            req.body.address,
            req.body.salary,
            req.file.filename, // Ensure filename is available
            req.body.category_id
        ];

        con.query(sql, [values], (err, result) => {
            if (err) return res.json({ Status: false, Error: "Query Error: " + err });
            return res.json({ Status: true });
        });
    });
});

// Get All Employees
router.get('/employee', (req, res) => {
    const sql = "SELECT * FROM employee";
    con.query(sql, (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" });
        return res.json({ Status: true, Result: result });
    });
});

// Get Employee by ID
router.get('/employee/:id', (req, res) => {
    const id = req.params.id;
    const sql = "SELECT * FROM employee WHERE id = ?";
    con.query(sql, [id], (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" });
        return res.json({ Status: true, Result: result });
    });
});

// Edit Employee
router.put('/edit_employee/:id', (req, res) => {
    const id = req.params.id;
    const sql = `UPDATE employee 
                 SET name = ?, email = ?, salary = ?, address = ?, category_id = ? 
                 WHERE id = ?`;

    const values = [
        req.body.name,
        req.body.email,
        req.body.salary,
        req.body.address,
        req.body.category_id
    ];

    con.query(sql, [...values, id], (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" + err });
        return res.json({ Status: true, Result: result });
    });
});

// Delete Employee
router.delete('/delete_employee/:id', (req, res) => {
    const id = req.params.id;
    const sql = "DELETE FROM employee WHERE id = ?";
    con.query(sql, [id], (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" + err });
        return res.json({ Status: true, Result: result });
    });
});

// Admin Count
router.get('/admin_count', (req, res) => {
    const sql = "SELECT COUNT(id) AS admin FROM admin";
    con.query(sql, (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" + err });
        return res.json({ Status: true, Result: result });
    });
});

// Employee Count
router.get('/employee_count', (req, res) => {
    const sql = "SELECT COUNT(id) AS employee FROM employee";
    con.query(sql, (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" + err });
        return res.json({ Status: true, Result: result });
    });
});

// Salary Sum
router.get('/salary_count', (req, res) => {
    const sql = "SELECT SUM(salary) AS salaryOFEmp FROM employee";
    con.query(sql, (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" + err });
        return res.json({ Status: true, Result: result });
    });
});

// Get Admin Records
router.get('/admin_records', (req, res) => {
    const sql = "SELECT * FROM admin";
    con.query(sql, (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query Error" + err });
        return res.json({ Status: true, Result: result });
    });
});

// Logout Route
router.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ Status: true });
});

export { router as adminRouter };