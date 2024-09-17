import express, { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import { DbUser } from "../types/user";
import { query, run } from "../utils/dbUtils";

const router: Router = express.Router();

// GET /users - ดึงข้อมูลผู้ใช้ทั้งหมด
router.get("/", async (req: Request, res: Response) => {
  try {
    const users = await query("SELECT * FROM users");
    res.json(users);
  } catch (error) {
    console.error("เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดขณะดึงข้อมูลผู้ใช้" });
  }
});

// GET /users/:id - ดึงข้อมูลผู้ใช้ตาม ID
router.get("/:id", async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const users = await query("SELECT * FROM users WHERE id = ?", [id]);
    if (users.length === 0) {
      return res.status(404).json({ message: "ไม่พบผู้ใช้" });
    }
    res.json(users[0]);
  } catch (error) {
    console.error("เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้ตาม ID:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดขณะดึงข้อมูลผู้ใช้" });
  }
});

// PUT /users/:id - อัพเดทข้อมูลผู้ใช้ตาม ID
router.put("/:id", async (req: Request, res: Response) => {
  const { id } = req.params;
  const userData: Partial<DbUser> = req.body; // ใช้ Partial สำหรับฟิลด์ที่ไม่บังคับ

  try {
    // ตรวจสอบว่ามีผู้ใช้ที่อีเมลเดียวกันอยู่แล้วหรือไม่ (ยกเว้นผู้ใช้ปัจจุบัน)
    if (userData.email) {
      const existingUsers = await query(
        "SELECT * FROM users WHERE email = ? AND id != ?",
        [userData.email, id]
      );

      if (existingUsers.length > 0) {
        return res.status(400).json({ message: "อีเมลนี้มีอยู่แล้ว" });
      }
    }

    // เตรียมคำสั่งอัพเดท
    const updateFields: string[] = [];
    const updateValues: any[] = [];

    if (userData.email) {
      updateFields.push("email = ?");
      updateValues.push(userData.email);
    }
    if (userData.first_name) {
      updateFields.push("first_name = ?");
      updateValues.push(userData.first_name);
    }
    if (userData.last_name) {
      updateFields.push("last_name = ?");
      updateValues.push(userData.last_name);
    }
    if (userData.password) {
      const hashedPassword = await bcrypt.hash(userData.password, 10);
      updateFields.push("password = ?");
      updateValues.push(hashedPassword);
    }
    if (userData.role) {
      updateFields.push("role = ?");
      updateValues.push(userData.role);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ message: "ไม่มีฟิลด์ให้ทำการอัพเดท" });
    }

    updateValues.push(id);

    const sql = `UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`;
    await run(sql, updateValues);

    res.json({ message: "อัพเดทข้อมูลผู้ใช้สำเร็จ" });
  } catch (error) {
    console.error("เกิดข้อผิดพลาดในการอัพเดทข้อมูลผู้ใช้:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดขณะอัพเดทข้อมูลผู้ใช้" });
  }
});

// DELETE /users/:id - ลบผู้ใช้ตาม ID
router.delete("/:id", async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    await run("DELETE FROM users WHERE id = ?", [id]);
    res.json({ message: "ลบข้อมูลผู้ใช้สำเร็จ" });
  } catch (error) {
    console.error("เกิดข้อผิดพลาดในการลบผู้ใช้:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดขณะลบข้อมูลผู้ใช้" });
  }
});

export default router;
