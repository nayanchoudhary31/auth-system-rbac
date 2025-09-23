import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// Graceful shutdown
const shutdown = async () => {
  try {
    await prisma.$disconnect();
  } catch (_) {}
};
process.on("beforeExit", shutdown);
process.on("SIGINT", async () => {
  await shutdown();
  process.exit(0);
});
process.on("SIGTERM", async () => {
  await shutdown();
  process.exit(0);
});

export default prisma;
