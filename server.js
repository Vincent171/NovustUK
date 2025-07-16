require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const OpenAI = require("openai");
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// API route
app.post("/api/ask", async (req, res) => {
  const { question } = req.body;

  const prompt = `You are a helpful UK tax assistant. Answer the following question clearly and simply, using up-to-date UK tax laws. Include estimates for tax if relevant, and note that this is not formal tax advice.\n\nQuestion: ${question}`;

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo", //VC - change to model 4 in future
      messages: [{ role: "user", content: prompt }],
      temperature: 0.7
    });

    const answer = completion.choices[0].message.content;
    res.json({ answer });
  } catch (err) {
    console.error(err);
    res.status(500).json({ answer: "Sorry, something went wrong." });
  }
});

// Serve frontend
app.use(express.static(path.join(__dirname)));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));