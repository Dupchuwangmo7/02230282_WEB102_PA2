import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { PrismaClient, Prisma } from '@prisma/client';
import { HTTPException } from 'hono/http-exception';
import { sign } from 'jsonwebtoken';
import * as bcrypt from 'bcryptjs'; // Correct import
import { jwt } from 'hono/jwt';
import type { JwtVariables } from 'hono/jwt';

type Variables = JwtVariables;

const app = new Hono<{ Variables: Variables }>();
const prisma = new PrismaClient();
const secret = 'mySecretKey';

app.use('/*', cors());

app.use(
  '/protected/*',
  jwt({
    secret: secret,
  })
);

// User registration
app.post('/register', async (c) => {
  try {
    const body = await c.req.json();
    const hashedPassword = await bcrypt.hash(body.password, 10);

    const user = await prisma.user.create({
      data: {
        email: body.email,
        password: hashedPassword,
      },
    });

    return c.json({ message: `${user.email} created successfully` });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError) {
      if (e.code === 'P2002') {
        return c.json({ message: 'Email already exists' }, 409);
      }
    }
    throw new HTTPException(500, { message: 'Internal server error' });
  }
});

// User login
app.post('/login', async (c) => {
  try {
    const body = await c.req.json();
    const user = await prisma.user.findUnique({
      where: { email: body.email },
    });

    if (!user) {
      return c.json({ message: 'User not found' }, 404);
    }

    const match = await bcrypt.compare(body.password, user.password);
    if (match) {
      const payload = {
        sub: user.id,
        exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expires in 60 minutes
      };
      const token = sign(payload, secret);
      return c.json({ message: 'Login successful', token: token });
    } else {
      throw new HTTPException(401, { message: 'Invalid credentials' });
    }
  } catch (error) {
    throw new HTTPException(401, { message: 'Invalid credentials' });
  }
});

// Get user's caught Pokémon
app.get('/protected/pokemons', async (c) => {
  const payload = c.get('jwtPayload');
  if (!payload) {
    throw new HTTPException(401, { message: 'Unauthorized' });
  }

  const pokemons = await prisma.pokemon.findMany({
    where: { userId: payload.sub },
  });

  return c.json({ data: pokemons });
});

// Create a new Pokémon
app.post('/protected/pokemons', async (c) => {
  const payload = c.get('jwtPayload');
  if (!payload) {
    throw new HTTPException(401, { message: 'Unauthorized' });
  }

  const body = await c.req.json();
  const pokemon = await prisma.pokemon.create({
    data: {
      name: body.name,
      type: body.type,
      caughtBy: body.caughtBy,
      userId: payload.sub,
    },
  });

  return c.json({ data: pokemon }, 201);
});

// Update a Pokémon
app.put('/protected/pokemons/:id', async (c) => {
  const payload = c.get('jwtPayload');
  if (!payload) {
    throw new HTTPException(401, { message: 'Unauthorized' });
  }

  const { id } = c.req.param();
  const body = await c.req.json();

  const pokemon = await prisma.pokemon.update({
    where: { id },
    data: {
      name: body.name,
      type: body.type,
    },
  });

  return c.json({ data: pokemon });
});

// Delete a Pokémon
app.delete('/protected/pokemons/:id', async (c) => {
  const payload = c.get('jwtPayload');
  if (!payload) {
    throw new HTTPException(401, { message: 'Unauthorized' });
  }

  const { id } = c.req.param();
  await prisma.pokemon.delete({
    where: { id },
  });

  return c.text('Deleted');
});

// Pagination for Pokémon
app.get('/pokemons', async (c) => {
  const page = parseInt(c.req.query('page') || '1', 10);
  const limit = parseInt(c.req.query('limit') || '10', 10);
  const skip = (page - 1) * limit;

  const pokemons = await prisma.pokemon.findMany({
    skip,
    take: limit,
  });

  const total = await prisma.pokemon.count();
  return c.json({ data: pokemons, total, page, limit });
});

// Get a single Pokémon by ID
app.get('/pokemons/:id', async (c) => {
  const { id } = c.req.param();
  const pokemon = await prisma.pokemon.findUnique({
    where: { id },
  });

  if (!pokemon) {
    throw new HTTPException(404, { message: 'Pokemon not found' });
  }

  return c.json({ data: pokemon });
});

export default app;
