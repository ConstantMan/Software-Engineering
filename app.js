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
.connect(process.env.MONGO_URI)
.then(() => console.log("Connected to MongoDB"))
.catch((err) => console.error("Could not connect to MongoDB:", err));


// Models
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: {
    type: String,
    enum: ["USER", "ADMIN", "ARTIST", "STAFF", "ORGANIZER"],
    required: true,
  },
  accountStatus: {
    type: String,
    enum: ["ACTIVE", "INACTIVE"],
    default: "ACTIVE",
  },
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
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  state: {
    type: String,
    enum: [
      "CREATED",
      "SUBMITTED",
      "REVIEWED",
      "APPROVED",
      "REJECTED",
      "SCHEDULED",
      "FINAL_SUBMITTED",
    ],
    default: "CREATED",
  },
  staffAssigned: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  review: {
    score: Number,
    comments: String,
  },
  setlist: [String], // Προστέθηκε για τη λίστα τραγουδιών
  preferredRehearsalSlots: [String], // Προστέθηκε για τις ώρες πρόβας
  preferredPerformanceSlots: [String], // Προστέθηκε για τις ώρες εμφάνισης
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

// Helper function for role-based access
const authorize = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).send("Access denied.");
  }
  next();
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
    res.status(400).send(error);
  }
});

/* User Login Old
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
});*/

// User Login
app.post("/users/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Εύρεση χρήστη με το username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).send("Invalid username or password.");
    }

    // Έλεγχος κατάστασης λογαριασμού
    if (user.accountStatus === "INACTIVE") {
      return res.status(403).send("Account is inactive. Contact an administrator.");
    }

    // Επαλήθευση κωδικού
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Invalid username or password.");
    }

    // Δημιουργία JWT token
    const token = jwt.sign(
      { _id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.send({ token });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Change Password
app.post("/users/change-password", authenticate, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    // Επαλήθευση αν παρέχονται τα πεδία
    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .send("Old password and new password are required.");
    }

    // Εύρεση χρήστη από το token
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).send("User not found.");
    }

    // Επαλήθευση παλιού κωδικού
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).send("Old password is incorrect.");
    }

    // Αλλαγή κωδικού
    user.password = newPassword;
    await user.save();

    res.status(200).send("Password updated successfully.");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Change User Account Status
app.post("/users/:id/status", authenticate, authorize(["ADMIN"]), async (req, res) => {
  try {
    const { status } = req.body;

    // Επαλήθευση αν παρέχεται έγκυρη κατάσταση
    if (!["ACTIVE", "INACTIVE"].includes(status)) {
      return res.status(400).send("Invalid status. Use 'ACTIVE' or 'INACTIVE'.");
    }

    // Εύρεση του χρήστη από το ID
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send("User not found.");
    }

    // Ενημέρωση της κατάστασης του λογαριασμού
    user.accountStatus = status;
    await user.save();

    res.status(200).send(`User status updated to ${status}.`);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Delete User
app.delete(
  "/users/:id",
  authenticate,
  authorize(["ADMIN"]),
  async (req, res) => {
    try {
      const user = await User.findByIdAndDelete(req.params.id);
      if (!user) {
        return res.status(404).send("User not found.");
      }
      res.status(200).send("User deleted successfully.");
    } catch (error) {
      res.status(500).send(error.message);
    }
  }
);

// Create Festival
app.post(
  "/festivals",
  authenticate,
  authorize(["ADMIN", "ORGANIZER"]),
  async (req, res) => {
    try {
      const { name, description, dates, venue } = req.body;

      // Ensure unique festival name
      const existingFestival = await Festival.findOne({ name });
      if (existingFestival) {
        return res.status(400).send("Festival name must be unique.");
      }

      const festival = new Festival({
        name,
        description,
        dates,
        venue,
        organizers: [req.user._id],
      });

      await festival.save();
      res.status(201).send(festival);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Get Festival by ID
app.get("/festivals/:id", authenticate, async (req, res) => {
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

// Start Assignment Phase
app.post(
  "/festivals/:id/start-assignment",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);
      if (!festival) return res.status(404).send("Festival not found.");
      if (festival.state !== "SUBMISSION") {
        return res
          .status(400)
          .send("Festival must be in SUBMISSION state to start assignment.");
      }
      festival.state = "ASSIGNMENT";
      await festival.save();
      res.status(200).send(festival);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Start Review Phase
app.post(
  "/festivals/:id/start-review",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);
      if (!festival) return res.status(404).send("Festival not found.");
      if (festival.state !== "ASSIGNMENT") {
        return res
          .status(400)
          .send("Festival must be in ASSIGNMENT state to start review.");
      }
      festival.state = "REVIEW";
      await festival.save();
      res.status(200).send(festival);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Start Submission Phase
app.post(
  "/festivals/:id/start-submission",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);

      if (!festival) return res.status(404).send("Festival not found.");
      if (festival.state !== "CREATED") {
        return res
          .status(400)
          .send("Festival must be in CREATED state to start submissions.");
      }

      festival.state = "SUBMISSION";
      await festival.save();
      res.status(200).send(festival);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Create Performance
app.post("/performances", authenticate, async (req, res) => {
  try {
    const { festival, name, description, genre, duration, bandMembers } =
      req.body;

    // Check festival existence and state
    const festivalDoc = await Festival.findById(festival);
    if (!festivalDoc) {
      return res.status(404).send("Festival not found.");
    }

    // Ensure unique performance name within the festival
    const existingPerformance = await Performance.findOne({ festival, name });
    if (existingPerformance) {
      return res
        .status(400)
        .send("Performance name must be unique within the festival.");
    }

    const performance = new Performance({
      festival,
      name,
      description,
      genre,
      duration,
      bandMembers,
      creator: req.user._id,
    });

    await performance.save();
    res.status(201).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Submit Performance
app.post("/performances/:id/submit", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findById(req.params.id);

    if (!performance) return res.status(404).send("Performance not found.");
    if (performance.creator.toString() !== req.user._id) {
      return res
        .status(403)
        .send("Only the creator can submit this performance.");
    }

    const festival = await Festival.findById(performance.festival);
    if (festival.state !== "SUBMISSION") {
      return res.status(400).send("Festival is not in submission phase.");
    }

    performance.state = "SUBMITTED";
    await performance.save();
    res.status(200).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Review Performance
app.post(
  "/performances/:id/review",
  authenticate,
  authorize(["STAFF"]),
  async (req, res) => {
    try {
      const performance = await Performance.findById(req.params.id);

      if (!performance) return res.status(404).send("Performance not found.");

      // Check if the performance is in the correct state
      if (performance.state !== "SUBMITTED") {
        return res
          .status(400)
          .send("Performance must be in SUBMITTED state to be reviewed.");
      }

      // Check if the logged-in user is the assigned STAFF
      if (performance.staffAssigned.toString() !== req.user._id) {
        return res
          .status(403)
          .send("Only the assigned staff member can review this performance.");
      }

      const { score, comments } = req.body;

      if (!score || !comments) {
        return res
          .status(400)
          .send("Score and comments are required for review.");
      }

      performance.review = { score, comments };
      performance.state = "REVIEWED";

      await performance.save();

      res.status(200).send(performance);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Approve Performance
app.post(
  "/performances/:id/approve",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const performance = await Performance.findById(req.params.id);

      if (!performance) return res.status(404).send("Performance not found.");

      // Check if the performance is in the correct state
      if (performance.state !== "REVIEWED") {
        return res
          .status(400)
          .send("Performance must be in REVIEWED state to be approved.");
      }

      performance.state = "APPROVED";
      await performance.save();

      res.status(200).send(performance);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Final Submission for Performance
app.post("/performances/:id/final-submit", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findById(req.params.id);

    if (!performance) return res.status(404).send("Performance not found.");

    // Check if the performance is in the right state for final submission
    if (performance.state !== "APPROVED") {
      return res
        .status(400)
        .send("Performance must be in APPROVED state for final submission.");
    }

    // Extract final submission details from the request body
    const { setlist, preferredRehearsalSlots, preferredPerformanceSlots } =
      req.body;

    if (!setlist || !preferredRehearsalSlots || !preferredPerformanceSlots) {
      return res
        .status(400)
        .send("All fields are required for final submission.");
    }

    // Update performance details
    performance.setlist = setlist;
    performance.preferredRehearsalSlots = preferredRehearsalSlots;
    performance.preferredPerformanceSlots = preferredPerformanceSlots;
    performance.state = "FINAL_SUBMITTED";

    await performance.save();

    res.status(200).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Update Performance
app.put("/performances/:id", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findById(req.params.id);

    if (!performance) return res.status(404).send("Performance not found.");
    if (performance.creator.toString() !== req.user._id) {
      return res
        .status(403)
        .send("Only the creator can update this performance.");
    }

    Object.assign(performance, req.body);
    await performance.save();
    res.status(200).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Withdraw Performance
app.delete("/performances/:id", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findById(req.params.id);

    if (!performance) return res.status(404).send("Performance not found.");
    if (performance.state === "SUBMITTED") {
      return res.status(400).send("Cannot withdraw a submitted performance.");
    }
    if (performance.creator.toString() !== req.user._id) {
      return res
        .status(403)
        .send("Only the creator can withdraw this performance.");
    }

    await performance.deleteOne();
    res.status(200).send("Performance withdrawn successfully.");
  } catch (error) {
    res.status(400).send(error);
  }
});

// Assign Staff to Performance
app.post(
  "/performances/:id/assign-staff",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const performance = await Performance.findById(req.params.id);

      if (!performance) return res.status(404).send("Performance not found.");

      const { staffId } = req.body;
      const staff = await User.findById(staffId);

      if (!staff || staff.role !== "STAFF") {
        return res.status(400).send("Invalid staff member.");
      }

      performance.staffAssigned = staffId;
      await performance.save();

      res.status(200).send(performance);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
