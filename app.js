// Entry point of the application
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Database Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Could not connect to MongoDB:", err));

// Models
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["USER", "ADMIN"], required: true },
});

UserSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model("User", UserSchema);

const FestivalSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
  description: String,
  dates: { start: Date, end: Date },
  venue: String,
  organizers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  state: {
    type: String,
    enum: [
      "CREATED",
      "SUBMISSION",
      "ASSIGNMENT",
      "REVIEW",
      "SCHEDULING",
      "FINAL_SUBMISSION",
      "DECISION",
      "ANNOUNCED",
    ],
    default: "CREATED",
  },
});
const Festival = mongoose.model("Festival", FestivalSchema);

const PerformanceSchema = new mongoose.Schema({
  festival: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Festival",
    required: true,
  },
  name: { type: String, required: true },
  description: String,
  genre: String,
  duration: Number,
  bandMembers: [String],
  state: {
    type: String,
    enum: [
      "CREATED",
      "SUBMITTED",
      "REVIEWED",
      "APPROVED",
      "REJECTED",
      "SCHEDULED",
    ],
    default: "CREATED",
  },
  createdAt: { type: Date, default: Date.now },
});
const Performance = mongoose.model("Performance", PerformanceSchema);

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Access denied. No token provided.");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).send("Invalid token.");
  }
};

// Routes
// User Registration
app.post("/users/register", async (req, res) => {
    try {
      const { username, password, role } = req.body;
      const user = new User({ username, password, role });
      await user.save();
      res.status(201).send("User registered successfully.");
    } catch (error) {
      if (error.code === 11000) {
        res.status(400).send("Username already exists. Please choose a different username.");
      } else {
        res.status(400).send(error);
      }
    }
  });
  
// User Login
app.post("/users/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).send("Invalid username or password.");
    }
    const token = jwt.sign(
      { _id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.send({ token });
  } catch (error) {
    res.status(400).send(error);
  }
});

// Create Festival
app.post("/festivals", authenticate, async (req, res) => {
  if (req.user.role !== "ADMIN") return res.status(403).send("Access denied.");
  try {
    const festival = new Festival(req.body);
    await festival.save();
    res.status(201).send(festival);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Get All Festivals
app.get("/festivals", async (req, res) => {
  try {
    const festivals = await Festival.find().populate("organizers", "username");
    res.status(200).send(festivals);
  } catch (error) {
    res.status(500).send(error);
  }
});

// Get Festival by ID
app.get("/festivals/:id", async (req, res) => {
  try {
    const festival = await Festival.findById(req.params.id).populate(
      "organizers",
      "username"
    );
    if (!festival) return res.status(404).send("Festival not found.");
    res.status(200).send(festival);
  } catch (error) {
    res.status(500).send(error);
  }
});

// Update Festival
app.put("/festivals/:id", authenticate, async (req, res) => {
  if (req.user.role !== "ADMIN") return res.status(403).send("Access denied.");
  try {
    const festival = await Festival.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!festival) return res.status(404).send("Festival not found.");
    res.status(200).send(festival);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Delete Festival
app.delete("/festivals/:id", authenticate, async (req, res) => {
  if (req.user.role !== "ADMIN") return res.status(403).send("Access denied.");
  try {
    const festival = await Festival.findByIdAndDelete(req.params.id);
    if (!festival) return res.status(404).send("Festival not found.");
    res.status(200).send("Festival deleted successfully.");
  } catch (error) {
    res.status(500).send(error);
  }
});

// Create Performance
app.post("/performances", authenticate, async (req, res) => {
  try {
    const performance = new Performance(req.body);
    await performance.save();
    res.status(201).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Get Performances by Festival
app.get("/festivals/:id/performances", async (req, res) => {
  try {
    const performances = await Performance.find({ festival: req.params.id });
    res.status(200).send(performances);
  } catch (error) {
    res.status(500).send(error);
  }
});

// Update Performance
app.put("/performances/:id", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!performance) return res.status(404).send("Performance not found.");
    res.status(200).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Delete Performance
app.delete("/performances/:id", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findByIdAndDelete(req.params.id);
    if (!performance) return res.status(404).send("Performance not found.");
    res.status(200).send("Performance deleted successfully.");
  } catch (error) {
    res.status(500).send(error);
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
