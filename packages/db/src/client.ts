import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from './generated/prisma/client.js';

let client: PrismaClient | undefined;

/** Lazily-created singleton — avoids opening a new connection pool per import in a
 * long-running worker or API process. Prisma 7 requires an explicit driver adapter rather
 * than reading DATABASE_URL implicitly. */
export function getPrismaClient(): PrismaClient {
  client ??= new PrismaClient({
    adapter: new PrismaPg({ connectionString: process.env['DATABASE_URL'] }),
  });
  return client;
}
