import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { query } from "../utils/dbUtils";

const authMiddleware = async (
  req: Request | any,
  res: Response,
  next: NextFunction
) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "ไม่พบ token กรุณาเข้าสู่ระบบ" });
  }

  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET || "defaultSecret")
    const currentTimestamp = Math.floor(Date.now() / 1000);

    if (decoded.exp && decoded.exp < currentTimestamp) {
      return res.status(401).json({ error: "Token หมดอายุ กรุณาเข้าสู่ระบบใหม่" });
    } else if (process.env.NODE_ENV === "development") {
      console.log("token expire in " + (decoded.exp - currentTimestamp) + " seconds");
    }

    const tokens = await query("SELECT * FROM refresh_tokens WHERE token = ? AND status = 'active'", [decoded.refresh_token]);
    if (tokens.length === 0) {
      return res.status(401).json({ error: "เซสชั่นหมดอายุ กรุณาเข้าสู่ระบบใหม่" });
    }

    req.user = decoded;
    await deleteExpiredTokens();
    next();
  } catch (error: any) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token หมดอายุ" });
    } else {
      return res.status(401).json({ error: "Token ไม่ถูกต้อง" });
    }
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

const deleteExpiredTokens = async () => {
  try {
    const date = new Date();
    date.setFullYear(date.getFullYear() - 1);
    const isoDateMinusOneYear = date.toISOString();
    await query(`
        DELETE FROM refresh_tokens
        WHERE status = 'revoked'
        AND expires_at < ?
    `, [
      isoDateMinusOneYear,
    ]);
  } catch (error) {
    console.error("เกิดข้อผิดพลาดในการลบโทเค็นที่หมดอายุ:", error);
  }
};

export { authMiddleware, adminGuard };
