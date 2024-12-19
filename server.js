const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const authRouter = require("./routes/auth/auth-routes");
mongoose
  .connect("mongodb+srv://arunks002info:arundata@cluster0.g3wgmd7.mongodb.net/")
  .then(() => console.log("MongoDB connected"))
  .catch((error) => console.log(error));

const app = express();
const PORT = process.env.PORT || 5000;

cors({
  origin: "http://127.0.0.1:5173/",
  methods: ["GET", "POST", "DELETE", "PUT"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "Cache-Control",
    "Expires",
    "Pragma",
  ],
  credentials: true,
});
// );

app.use(cookieParser());
app.use(express.json());
app.use("/api/auth", authRouter);
app.listen(PORT, () => console.log(`Server is now running on port ${PORT}`));
