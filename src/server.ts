import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import { prismaClient } from "./prisma/client";
import Jwt from "jsonwebtoken";
import { SECRET, SECURITY_ROLE } from "./security";

const app = express();
app.use(cors());
app.use(express.json());

app.post("/auth/register", async (request, response) => {
  const { email, username, name, password, confirmPassword, role } =
    request.body;

  if (!email || !name || !password || !username || !confirmPassword) {
    return response
      .status(422)
      .json({ error: "Todos os campos são obrigatórios" });
  }

  if (password !== confirmPassword) {
    return response.status(400).json({ error: "A senha precisa ser igual" });
  }

  const verifyIfExistsUser = await prismaClient.user.findFirst({
    where: {
      username,
      OR: {
        email,
      },
    },
  });

  if (verifyIfExistsUser)
    return response
      .status(400)
      .json({ error: "Usurário já cadastrado com esse username ou email" });

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const userCreated = await prismaClient.user.create({
    data: {
      username,
      name,
      email,
      password: passwordHash,
      role: role === SECURITY_ROLE.ADMIN ? role : SECURITY_ROLE.USER,
    },
  });

  return response.json(userCreated);
});

app.get("/auth/login", async (request, response) => {
  const { username, password } = request.body;

  if (!username && !password) {
    return response.status(422).json({ error: "Preencha email e senha" });
  }

  const user = await prismaClient.user.findFirst({
    where: {
      username,
    },
  });

  if (!user)
    return response.status(404).json({ error: "Usurário não encontrado" });

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword)
    return response.status(400).json({ error: "Credenciais inválidas" });

  const secret = SECRET;
  const token = Jwt.sign(
    {
      id: user.id,
      role: user.role,
    },
    secret
  );

  return response
    .status(200)
    .json({ success: "Usuário logado com sucesso!", token });
});

app.post("/cards", checkToken, async (request, response) => {
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
    return response.status(400).json({ error: "Carta já cadastrada" });

  const cardCreated = await prismaClient.card.create({
    data: {
      name,
      imageUrl,
    },
  });

  return response.json(cardCreated);
});

app.put("/cards", checkToken, async (request, response) => {
  const { name, imageUrl } = request.body;

  const verifyIfExistsCard = await prismaClient.card.findFirst({
    where: {
      name,
    },
  });

  if (!verifyIfExistsCard)
    return response.status(400).json({ error: "Carta ainda não cadastrada" });

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

function checkToken(request: Request, response: Response, next: NextFunction) {
  const authHeader = request.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return response.status(401).json({ error: "Acesso não autorizado" });
  }

  try {
    const secret = SECRET;
    Jwt.verify(token, secret!);
    next();
  } catch (error) {
    response.status(400).json({ error: "Token inválido" });
  }
}

app.listen(3333, () => console.log("Server is runnig in port 3333"));
