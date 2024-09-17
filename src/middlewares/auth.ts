import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { query } from "../utils/dbUtils";

const authMiddleware = (
  req: Request | any,
  res: Response,
  next: NextFunction
) => {
  // รับโทเค็นจาก header Authorization
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "ไม่พบ token กรุณาเข้าสู่ระบบ" });
  }

  try {
    // ตรวจสอบความถูกต้องของโทเค็น
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET || "defaultSecret");

    // ตรวจสอบว่าโทเค็นหมดอายุหรือไม่
    const currentTimestamp = Math.floor(Date.now() / 1000);
    if (decoded.exp && decoded.exp < currentTimestamp) {
      return res.status(401).json({ error: "Token หมดอายุ กรุณาเข้าสู่ระบบใหม่" });
    }

    // ตรวจสอบสถานะของโทเค็นในฐานข้อมูล
    query("SELECT * FROM refresh_tokens WHERE token = ? AND status = 'active'", [token])
      .then((tokens) => {
        if (tokens.length === 0) {
          return res.status(401).json({ error: "Token ได้รับการเพิกถอน กรุณาเข้าสู่ระบบใหม่" });
        }

        // กำหนดข้อมูลผู้ใช้ใน request
        req.user = decoded;

        // ทำงานต่อ
        next();
      })
      .catch((error) => {
        console.error("เกิดข้อผิดพลาดในการตรวจสอบสถานะของโทเค็น:", error);
        res.status(500).json({ error: "เกิดข้อผิดพลาดในการตรวจสอบสถานะของโทเค็น" });
      });
  } catch (error) {
    console.log("Token verification error:", error);
    return res.status(401).json({ error: "Token ไม่ถูกต้อง" });
  }
};

// Middleware สำหรับการตรวจสอบสิทธิ์ของผู้ดูแลระบบ
const adminGuard = (req: Request | any, res: Response, next: NextFunction) => {
  // ตรวจสอบว่า user มีสิทธิ์เป็นผู้ดูแลระบบหรือไม่
  if (req.user && req.user.role === 2) {
    next();
  } else {
    res.status(403).json({ error: "คุณไม่มีสิทธิ์เข้าถึงส่วนนี้ เฉพาะผู้ดูแลระบบเท่านั้น" });
  }
};

export { authMiddleware, adminGuard };
