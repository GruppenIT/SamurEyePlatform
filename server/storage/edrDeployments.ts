import { db } from "../db";
import { edrDeployments, type EdrDeployment, type InsertEdrDeployment } from "@shared/schema";
import { eq, desc } from "drizzle-orm";

export async function insertEdrDeployment(
  data: InsertEdrDeployment
): Promise<EdrDeployment> {
  const [row] = await db.insert(edrDeployments).values(data).returning();
  return row;
}

export async function getEdrDeploymentsByJourney(
  journeyId: string
): Promise<EdrDeployment[]> {
  return await db
    .select()
    .from(edrDeployments)
    .where(eq(edrDeployments.journeyId, journeyId))
    .orderBy(desc(edrDeployments.createdAt));
}
