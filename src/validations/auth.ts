import { Request, Response, NextFunction } from "express";
import { body, validationResult } from "express-validator";

// Middleware for validating user registration
const validateAuthRegisterBody = [
  body("email")
    .isEmail()
    .withMessage("กรุณากรอกอีเมลล์")
    .isLength({ min: 6, max: 50 })
    .withMessage("อีเมลล์ต้องมีความยาวระหว่าง 6 ถึง 50 ตัวอักษร"),
  body("last_name")
    .notEmpty()
    .withMessage("กรุณากรอกนามสกุล")
    .isLength({ min: 2, max: 50 })
    .withMessage("นามสกุลต้องมีความยาวระหว่าง 2 ถึง 50 ตัวอักษร")
    .matches(/^[ก-๙a-zA-Z\s]+$/)
    .withMessage("นามสกุลต้องเป็นภาษาไทยหรืออังกฤษเท่านั้น"),
  body("first_name")
    .notEmpty()
    .withMessage("กรุณากรอกชื่อ")
    .isLength({ min: 2, max: 50 })
    .withMessage("ชื่อต้องมีความยาวระหว่าง 2 ถึง 50 ตัวอักษร")
    .matches(/^[ก-๙a-zA-Z\s]+$/)
    .withMessage("ชื่อต้องเป็นภาษาไทยหรืออังกฤษเท่านั้น"),
  body("password")
    .notEmpty()
    .withMessage("กรุณากรอกรหัสผ่าน")
    .isLength({ min: 8, max: 32 })
    .withMessage("รหัสผ่านต้องมีความยาวระหว่าง 8 ถึง 32 ตัวอักษร"),
  body("password_confirmation")
    .notEmpty()
    .withMessage("กรุณายืนยันรหัสผ่าน")
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("รหัสผ่านยืนยันไม่ตรงกับรหัสผ่าน");
      }
      return true;
    }),
  (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
];

// Middleware for validating user login
const validateAuthLoginBody = [
  body("email")
    .isEmail()
    .withMessage("กรุณากรอกอีเมลล์")
    .isLength({ min: 6, max: 50 })
    .withMessage("อีเมลล์ต้องมีความยาวระหว่าง 6 ถึง 50 ตัวอักษร"),
  body("password")
    .notEmpty()
    .withMessage("กรุณากรอกรหัสผ่าน")
    .isLength({ min: 8, max: 32 })
    .withMessage("รหัสผ่านต้องมีความยาวระหว่าง 8 ถึง 32 ตัวอักษร"),
  (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
];

export { validateAuthRegisterBody, validateAuthLoginBody };
