import { db } from "../db";
import { edrDeployments, hosts, type EdrDeployment, type InsertEdrDeployment } from "@shared/schema";
import { eq, desc } from "drizzle-orm";

export type EdrDeploymentWithHost = EdrDeployment & {
  hostName: string | null;
  hostIps: string[];
  hostOperatingSystem: string | null;
};

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

export async function getEdrDeploymentsByJourneyWithHost(
  journeyId: string
): Promise<EdrDeploymentWithHost[]> {
  const rows = await db
    .select({
      id: edrDeployments.id,
      hostId: edrDeployments.hostId,
      journeyId: edrDeployments.journeyId,
      jobId: edrDeployments.jobId,
      deploymentTimestamp: edrDeployments.deploymentTimestamp,
      detectionTimestamp: edrDeployments.detectionTimestamp,
      deploymentMethod: edrDeployments.deploymentMethod,
      detected: edrDeployments.detected,
      testDuration: edrDeployments.testDuration,
      createdAt: edrDeployments.createdAt,
      hostName: hosts.name,
      hostIps: hosts.ips,
      hostOperatingSystem: hosts.operatingSystem,
    })
    .from(edrDeployments)
    .leftJoin(hosts, eq(edrDeployments.hostId, hosts.id))
    .where(eq(edrDeployments.journeyId, journeyId))
    .orderBy(desc(edrDeployments.createdAt));

  return rows as EdrDeploymentWithHost[];
}
