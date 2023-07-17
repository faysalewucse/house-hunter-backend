const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const saltRounds = parseInt(process.env.SALT_ROUNDS);

require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 5000;

app.get("/", (req, res) => {
  res.send("House Hunter Server is running.");
});

app.post("/jwt", (req, res) => {
  const user = req.body;
  const token = jwt.sign(user, process.env.JWT_SECRET_KEY, { expiresIn: "1h" });
  res.send({ token });
});

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = process.env.MONGODB_URL;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    client.connect();

    const database = client.db("houseHunterDB");
    const users = database.collection("users");

    // Check if the user email is already in use
    const checkUserExistence = async (email) => {
      const user = await users.findOne({ email });

      if (user) {
        return true;
      }

      return false;
    };

    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      try {
        const user = await users.findOne({ email: email });

        if (!user) {
          throw new Error("User not found");
        }

        const matchPassword = bcrypt.compareSync(password, user?.password);

        if (!matchPassword) {
          throw new Error("Password is incorrect");
        }

        res.send(user);
      } catch (error) {
        console.log(error.message);
        res.status(500).send({ message: error.message });
      }
    });

    app.post("/register", async (req, res) => {
      try {
        const user = req.body;
        const password = user.password;

        const hashedPassword = bcrypt.hashSync(password, saltRounds);

        if (checkUserExistence() === true) {
          throw new Error("Email already exists");
        }

        const result = await users.insertOne({
          ...user,
          password: hashedPassword,
        });

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`House Hunter Server listening on port ${port}`);
});
