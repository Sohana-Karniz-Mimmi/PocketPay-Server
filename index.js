const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bodyParser = require("body-parser");
const app = express();
const port = process.env.PORT || 5000;

const corsOptions = {
  origin: ["http://localhost:5173", "http://localhost:5174"],
  credentials: true,
  optionSuccessStatus: 200,
};

// Middleware
app.use(cors(corsOptions));
app.use(bodyParser.json());

//Start MongoDB here
// MongoDB URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.2xcjib6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

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
    // await client.connect();

    //Collections
    const usersCollection = client.db("PocketPay").collection("users");

    // Protect routes middleware
    const authenticateToken = (req, res, next) => {
      const token = req.header("Authorization");
      if (!token) return res.status(401).json({ error: "Access denied" });

      try {
        const verified = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = verified;
        next();
      } catch (error) {
        res.status(400).json({ error: "Invalid token" });
      }
    };

    // Create a new user
    app.put("/register", async (req, res) => {
      const { name, pin, role, mobile_number, email } = req.body;

      // Check if the user already exists
      const query = {
        $or: [{ email: email }, { mobile_number: mobile_number }],
      };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
      }
      // Hash the PIN
      const hashedPin = await bcrypt.hash(pin, 10);

      // save user for the first time
      const options = { upsert: true };
      const updateDoc = {
        $set: {
          name,
          pin: hashedPin,
          mobile_number,
          email,
          status: "Pending",
          role,
          balance: 0,
          timestamp: Date.now(),
        },
      };

      // Save the user to the database
      try {
        const result = await usersCollection.updateOne(
          query,
          updateDoc,
          options
        );
        res.status(201).json({
          message: "User registered, pending admin approval",
          userId: result.insertedId,
        });
      } catch (error) {
        res.status(500).json({ error: "Registration failed" });
      }
    });

    // Login endpoint
    app.post("/login", async (req, res) => {
      const { identifier, pin } = req.body;

      try {
        const user = await usersCollection.findOne({
          $or: [{ email: identifier }, { mobile_number: identifier }],
        });

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        const isPinValid = await bcrypt.compare(pin, user.pin);
        if (!isPinValid) {
          return res.status(401).json({ error: "Invalid PIN" });
        }

        const token = jwt.sign(
          { userId: user._id },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "1h" }
        );
        res.json({ token, user: { name: user.name, email: user.email } });
      } catch (error) {
        res.status(500).json({ error: "Login failed" });
      }
    });

    // Profile endpoint
    app.get("/profile", authenticateToken, async (req, res) => {
      try {
        const userId = req.user.userId;
        const user = await usersCollection.findOne(
          { _id: new ObjectId(userId) },
          { projection: { pin: 0 } }
        );
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }
        res.json({ user });
      } catch (error) {
        res.status(500).json({ error: "Failed to fetch user profile" });
      }
    });

    /***************Users****************************************** */

    // get a user info by email from db
    app.get("/user/:email", async (req, res) => {
      const email = req.params.email;
      const result = await usersCollection.findOne({ email });
      res.send(result);
    });

    // Get all users data from db for pagination
    app.get("/users", async (req, res) => {
      const size = parseInt(req.query.size);
      const page = parseInt(req.query.page) - 1;
      const filter = req.query.filter;
      const search = req.query.search;
      // console.log(filter, search)
      // console.log(size, page)

      let query = {
        name: { $regex: search, $options: "i" },
      };
      if (filter) query.role = filter;
      let options = {};
      // const result = await usersCollection.find(query, options).toArray();
      const result = await usersCollection
        .find(query, options)
        .skip(page * size)
        .limit(size)
        .toArray();
      // const result = await usersCollection.find().toArray();

      res.send(result);
    });

    // Get all users data count from db
    app.get("/users-count", async (req, res) => {
      const filter = req.query.filter;
      const search = req.query.search;
      let query = {
        name: { $regex: search, $options: "i" },
      };
      if (filter) query.name = filter;
      const count = await usersCollection.countDocuments(query);

      res.send({ count });
    });

    //update a user status
    app.patch("/users/update/:email", async (req, res) => {
      const email = req.params.email;
      const user = req.body;
      const query = { email };
      const updateDoc = {
        $set: { ...user, timestamp: Date.now() },
      };
      const result = await usersCollection.updateOne(query, updateDoc);
      res.send(result);
    });

    // Send Money endpoint

    app.post("/send-money", authenticateToken, async (req, res) => {
      const { recipientMobile, amount, pin } = req.body;

      // Validate amount
      if (amount < 50) {
        return res
          .status(400)
          .json({ error: "Minimum transaction amount is 50 Taka" });
      }

      try {
        // Verify sender's PIN
        const sender = await usersCollection.findOne({
          _id: new ObjectId(req.user.userId),
        });
        const isPinValid = await bcrypt.compare(pin, sender.pin);
        if (!isPinValid) {
          return res.status(401).json({ error: "Invalid PIN" });
        }

        // Check sender's balance
        let transactionFee = 0;
        if (amount > 100) {
          transactionFee = 5;
        }
        const totalAmount = amount + transactionFee;
        if (sender.balance < totalAmount) {
          return res.status(400).json({ error: "Insufficient balance" });
        }

        // Verify recipient exists
        const recipient = await usersCollection.findOne({
          mobile_number: recipientMobile,
        });
        if (!recipient) {
          return res.status(404).json({ error: "Mobile number not found" });
        }

        // Perform the transaction
        const session = client.startSession();
        session.startTransaction();
        try {
          await usersCollection.updateOne(
            { _id: sender._id },
            { $inc: { balance: -totalAmount } },
            { session }
          );
          await usersCollection.updateOne(
            { _id: recipient._id },
            { $inc: { balance: amount } },
            { session }
          );
          await session.commitTransaction();
        } catch (error) {
          await session.abortTransaction();
          throw error;
        } finally {
          session.endSession();
        }

        res.status(200).json({ message: "Transaction successful" });
      } catch (error) {
        res.status(500).json({ error: "Transaction failed" });
      }
    });
    // Send a ping to confirm a successful connection

    // Cash Out endpoint
    app.post("/cash-out", authenticateToken, async (req, res) => {
      const { agentMobile, amount, pin } = req.body;

      // Validate amount
      if (amount <= 0) {
        return res.status(400).json({ error: "Invalid transaction amount" });
      }

      try {
        // Verify user's PIN
        const user = await usersCollection.findOne({
          _id: new ObjectId(req.user.userId),
        });
        const isPinValid = await bcrypt.compare(pin, user.pin);
        if (!isPinValid) {
          return res.status(401).json({ error: "Invalid PIN" });
        }

        // Calculate fee
        const fee = amount * 0.015;
        const totalAmount = amount + fee;

        // Check user's balance
        if (user.balance < totalAmount) {
          return res.status(400).json({ error: "Insufficient balance" });
        }

        // Verify agent exists
        const agent = await usersCollection.findOne({
          mobile_number: agentMobile,
          role: "agent",
        });
        if (!agent) {
          return res.status(404).json({ error: "Agent not found" });
        }

        // Perform the transaction
        const session = client.startSession();
        session.startTransaction();
        try {
          await usersCollection.updateOne(
            { _id: user._id },
            { $inc: { balance: -totalAmount } },
            { session }
          );
          await usersCollection.updateOne(
            { _id: agent._id },
            { $inc: { balance: amount + fee } },
            { session }
          );
          await session.commitTransaction();
        } catch (error) {
          await session.abortTransaction();
          throw error;
        } finally {
          session.endSession();
        }

        res.status(200).json({ message: "Cash-out successful" });
      } catch (error) {
        res.status(500).json({ error: "Transaction failed" });
      }
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("PocketPay Server is Running");
});

app.listen(port, () => {
  console.log(`PocketPay server is running on port: ${port}`);
});
