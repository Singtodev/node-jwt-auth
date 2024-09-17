import express, { Request, Response } from "express";
import rateLimit from "express-rate-limit";
import bodyParser = require("body-parser");
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { authRouter, userRouter } from "./controllers";
import { authMiddleware } from "./middlewares/auth";
const session = require("express-session");
var morgan = require("morgan");
const app = express();
const port = process.env.PORT || 8000;
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 1000,
});
dotenv.config();
app.use(morgan("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(limiter);
app.use(cookieParser());
app.use(
  session({
    name: "app-name",
    secret: "app-name",
    cookie: { maxAge: 3 * 60 * 60 * 1000 },
    resave: false,
    saveUninitialized: false,
  })
);
app.get("/", (req: Request, res: Response) => {
  res.send("Hello World : [ app-name-api ]");
});
app.use("/api/auth", authRouter);
app.use("/api/users", authMiddleware, userRouter);
app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
});
