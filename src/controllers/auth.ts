import express, { Router, Request, Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { User, DbUser } from "../types/user";
import { query, run } from "../utils/dbUtils";
import {
  validateAuthLoginBody,
  validateAuthRegisterBody,
} from "../validations/auth";
import dotenv from "dotenv";
dotenv.config();

const router: Router = express.Router();
const secret = process.env.JWT_SECRET || "Enigma";
const jwtExpire = process.env.JWT_EXPIRE || "1h";
const refreshTokenExpire = process.env.JWT_REFRESH_EXPIRE || "7d";

// POST /register - ลงทะเบียนผู้ใช้ใหม่
router.post(
  "/register",
  validateAuthRegisterBody,
  async (req: Request, res: Response) => {
    const userData: User = req.body;

    try {
      // ตรวจสอบผู้ใช้ที่มีอยู่แล้ว
      const existingUsers = await query("SELECT * FROM users WHERE email = ?", [
        userData.email,
      ]);

      if (existingUsers.length > 0) {
        return res.status(400).json({ message: "อีเมลล์นี้มีอยู่แล้ว" });
      }

      // แฮชรหัสผ่าน
      const hashedPassword = await bcrypt.hash(userData.password, 10);

      // เพิ่มผู้ใช้ใหม่
      const result = await run(
        "INSERT INTO users (email, first_name, last_name, password) VALUES (?, ?, ?, ?)",
        [
          userData.email,
          userData.first_name,
          userData.last_name,
          hashedPassword,
        ]
      );

      const userId = result.lastID;
      const token = jwt.sign({ id: userId, ...userData }, secret, {
        expiresIn: jwtExpire,
      });
      const refreshToken = jwt.sign({ id: userId }, secret, {
        expiresIn: refreshTokenExpire,
      });

      await run(
        "INSERT INTO refresh_tokens (user_id, token, expires_at, status) VALUES (?, ?, ?, ?)",
        [
          userId,
          refreshToken,
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          'active',
        ]
      );

      res.status(201).json({
        message: "ลงทะเบียนสำเร็จ",
        data: { ...userData, id: userId },
        token,
        refreshToken,
      });
    } catch (error) {
      console.error("เกิดข้อผิดพลาดระหว่างการลงทะเบียน:", error);
      res.status(500).json({ message: "เกิดข้อผิดพลาดระหว่างการลงทะเบียน" });
    }
  }
);

// POST /login - เข้าสู่ระบบ
router.post(
  "/login",
  validateAuthLoginBody,
  async (req: Request, res: Response) => {
    const { email, password } = req.body;

    try {
      // ค้นหาผู้ใช้
      const users = await query("SELECT * FROM users WHERE email = ?", [email]);

      if (users.length === 0) {
        return res.status(401).json({ message: "อีเมลล์หรือรหัสผ่านไม่ถูกต้อง" });
      }

      const user: DbUser = users[0];

      // เปรียบเทียบรหัสผ่าน
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(401).json({ message: "ข้อมูลรับรองไม่ถูกต้อง" });
      }

      // ทำลาย refresh token เดิม
      await run("UPDATE refresh_tokens SET status = 'revoked' WHERE user_id = ? AND status = 'active'", [user.id]);

      // สร้าง token ใหม่
      const userData = {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
      };

      const token = jwt.sign(userData, secret, { expiresIn: jwtExpire });
      const refreshToken = jwt.sign({ id: user.id }, secret, {
        expiresIn: refreshTokenExpire,
      });

      // บันทึก refresh token ใหม่ในฐานข้อมูล
      await run(
        "INSERT INTO refresh_tokens (user_id, token, expires_at, status) VALUES (?, ?, ?, ?)",
        [
          user.id,
          refreshToken,
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          'active',
        ]
      );

      res.json({
        message: "เข้าสู่ระบบสำเร็จ",
        data: userData,
        token,
        refreshToken,
      });
    } catch (error) {
      console.error("เกิดข้อผิดพลาดระหว่างการเข้าสู่ระบบ:", error);
      res.status(500).json({ message: "เกิดข้อผิดพลาดระหว่างการเข้าสู่ระบบ" });
    }
  }
);

// POST /refresh - รีเฟรชโทเค็น
router.post("/refresh", async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  try {
    // ตรวจสอบว่า refreshToken มีอยู่ในฐานข้อมูลและยังไม่หมดอายุ
    const tokens = await query("SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > ? AND status = 'active'", [
      refreshToken,
      new Date().toISOString(),
    ]);

    if (tokens.length === 0) {
      return res.status(401).json({ message: "Refresh token ไม่ถูกต้องหรือหมดอายุ" });
    }

    const userId = tokens[0].user_id;
    const newToken = jwt.sign({ id: userId }, secret, { expiresIn: jwtExpire });
    const newRefreshToken = jwt.sign({ id: userId }, secret, {
      expiresIn: refreshTokenExpire,
    });

    // อัพเดต refresh token ในฐานข้อมูล
    await run(
      "UPDATE refresh_tokens SET token = ?, expires_at = ? WHERE token = ?",
      [
        newRefreshToken,
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        refreshToken,
      ]
    );

    res.json({
      message: "รีเฟรชโทเค็นสำเร็จ",
      token: newToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error("เกิดข้อผิดพลาดระหว่างการรีเฟรชโทเค็น:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดระหว่างการรีเฟรชโทเค็น" });
  }
});

// POST /revoke - เพิกถอน refreshToken
router.post("/revoke", async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  try {
    // เพิกถอน refresh token
    const result = await run("UPDATE refresh_tokens SET status = 'revoked' WHERE token = ?", [refreshToken]);

    if (result.changes === 0) {
      return res.status(404).json({ message: "Refresh token ไม่พบ" });
    }

    res.json({ message: "เพิกถอน refresh token สำเร็จ" });
  } catch (error) {
    console.error("เกิดข้อผิดพลาดระหว่างการเพิกถอนโทเค็น:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดระหว่างการเพิกถอนโทเค็น" });
  }
});

// POST /logout - ออกจากระบบ
router.post("/logout", async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  try {
    // ตรวจสอบว่า refreshToken มีอยู่ในฐานข้อมูลและยังไม่หมดอายุ
    const tokens = await query("SELECT * FROM refresh_tokens WHERE token = ? AND status = 'active'", [
      refreshToken,
    ]);

    if (tokens.length === 0) {
      return res.status(404).json({ message: "Refresh token ไม่พบหรือไม่ใช่ active" });
    }

    // เพิกถอน refresh token
    await run("UPDATE refresh_tokens SET status = 'revoked' WHERE token = ?", [refreshToken]);

    res.json({ message: "ออกจากระบบสำเร็จ" });
  } catch (error) {
    console.error("เกิดข้อผิดพลาดระหว่างการออกจากระบบ:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดระหว่างการออกจากระบบ" });
  }
});

export default router;
