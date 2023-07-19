const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { verifyJWT } = require("./middleware/verifyJWT");

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
  const email = req.body;

  const token = jwt.sign(email, process.env.JWT_SECRET_KEY, {
    expiresIn: "1h",
  });

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
    const houses = database.collection("houses");

    const verifyHouseOwner = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await users.findOne(query);
      if (user?.role !== "houseOwner") {
        return res
          .status(403)
          .send({ error: true, message: "forbidden message" });
      }
      next();
    };

    // Check if the user email is already in use
    const checkUserExistence = async (req, res, next) => {
      const { email } = req.body;
      const user = await users.findOne({ email });

      if (user) {
        return res
          .status(401)
          .send({ error: true, message: "E-mail already in use" });
      }

      next();
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

    app.post("/register", checkUserExistence, async (req, res) => {
      try {
        const user = req.body;
        const password = user.password;

        const hashedPassword = bcrypt.hashSync(password, saltRounds);

        const result = await users.insertOne({
          ...user,
          password: hashedPassword,
        });

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    app.post("/house", verifyJWT, verifyHouseOwner, async (req, res) => {
      try {
        const house = req.body;

        const result = await houses.insertOne(house);

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    app.get("/houses", async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const city = req.query.city || null;

        let query = {};

        if (city) {
          query.city = city;
        }

        const limit = 10; // Set the desired limit per page

        const skip = (page - 1) * limit;
        const totalHouse = await houses.countDocuments(query);
        const cursor = houses.find(query).skip(skip).limit(limit);
        const result = await cursor.toArray();

        res.send({ data: result, totalHouse });
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    app.get(
      "/houses/:houseOwner",
      verifyJWT,
      verifyHouseOwner,
      async (req, res) => {
        try {
          const houseOwner = req.params.houseOwner;

          const cursor = houses.find({ houseOwner });
          const result = await cursor.toArray();

          res.send(result);
        } catch (error) {
          res.status(500).send({ message: error.message });
        }
      }
    );

    app.get("/users/:userEmail", async (req, res) => {
      const email = req.params.userEmail;
      const result = await users.findOne({ email: email });
      res.send(result);
    });

    app.patch("/houses/:houseId", verifyJWT, verifyHouseOwner, (req, res) => {
      const houseId = req.params.houseId;
      const newData = req.body;

      const result = houses.updateOne(
        { _id: new ObjectId(houseId) },
        { $set: newData }
      );

      res.send(result);
    });

    app.delete(
      "/houses/:houseId",
      verifyJWT,
      verifyHouseOwner,
      async (req, res) => {
        const result = await houses.deleteOne({
          _id: new ObjectId(req.params.houseId),
        });

        if (result.deletedCount === 1) {
          res.send(result);
        } else {
          res.send({ error: "House not found." });
        }
      }
    );

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
