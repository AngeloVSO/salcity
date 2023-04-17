import express from "express";
import { prismaClient } from "./prisma/client";

const app = express();
app.use(express.json());

app.post("/users", async (request, response) => {
  const { email, username, name } = request.body;

  const verifyIfExistsUser = await prismaClient.user.findFirst({
    where: {
      username,
      OR: {
        email,
      },
    },
  });

  if (verifyIfExistsUser)
    return response.status(400).json({ error: "User already exists" });

  const userCreated = await prismaClient.user.create({
    data: {
      email,
      username,
      name,
    },
  });

  return response.json(userCreated);
});

app.post("/cards", async (request, response) => {
  const { name, imageUrl } = request.body;

  const verifyIfExistsCard = await prismaClient.card.findFirst({
    where: {
      name,
      OR: {
        imageUrl,
      },
    },
  });

  if (verifyIfExistsCard)
    return response.status(400).json({ error: "Card already exists" });

  const cardCreated = await prismaClient.card.create({
    data: {
      name,
      imageUrl,
    },
  });

  return response.json(cardCreated);
});

app.put("/cards", async (request, response) => {
  const { name, imageUrl } = request.body;

  const verifyIfExistsCard = await prismaClient.card.findFirst({
    where: {
      name,
    },
  });

  if (!verifyIfExistsCard)
    return response.status(400).json({ error: "Card doesn't exists" });

  const cardCreated = await prismaClient.card.update({
    where: {
      name,
    },
    data: {
      imageUrl,
    },
  });

  return response.json(cardCreated);
});

app.get("/cards/:name", async (request, response) => {
  const { name } = request.params;

  const card = await prismaClient.card.findFirst({
    where: {
      name,
    },
  });

  return response.json(card);
});

app.get("/cards", async (request, response) => {
  const cards = await prismaClient.card.findMany();

  return response.json(cards);
});

app.listen(3333, () => console.log("Server is runnig in port 3333"));
