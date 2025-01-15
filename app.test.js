const request = require("supertest");
const mongoose = require("mongoose");
const app = require("./app"); // Import the app instance

beforeAll(async () => {
  // Connect to the test database
  await mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
});

afterAll(async () => {
  // Drop the database and close the connection
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
});

describe("User API", () => {
  let token;

  it("should register a new user", async () => {
    const res = await request(app)
      .post("/users/register")
      .send({
        username: "testuser",
        password: "Password123!",
        confirmPassword: "Password123!",
        role: "USER",
      });

    expect(res.statusCode).toEqual(201);
    expect(res.text).toEqual("User registered successfully.");
  });

  it("should not register a user with duplicate username", async () => {
    const res = await request(app)
      .post("/users/register")
      .send({
        username: "testuser",
        password: "Password123!",
        confirmPassword: "Password123!",
        role: "USER",
      });

    expect(res.statusCode).toEqual(400);
    expect(res.body).toHaveProperty("message", "Username is already taken.");
  });

  it("should log in the user and return a token", async () => {
    const res = await request(app)
      .post("/users/login")
      .send({
        username: "testuser",
        password: "Password123!",
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("token");
    token = res.body.token; // Save token for future requests
  });
});
