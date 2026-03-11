import { db } from "../db";
import {
  journeys,
  schedules,
  jobs,
  jobResults,
  journeyCredentials,
  credentials,
  type Journey,
  type InsertJourney,
  type Schedule,
  type InsertSchedule,
  type Job,
  type InsertJob,
  type JobResult,
  type JourneyCredential,
  type InsertJourneyCredential,
  type Credential,
} from "@shared/schema";
import { eq, desc, inArray } from "drizzle-orm";
import { sanitizeString, sanitizeObject } from "./utils";
import { createLogger } from '../lib/logger';

const log = createLogger('storage');

// Journey operations
export async function getJourneys(): Promise<Journey[]> {
  return await db.select().from(journeys).orderBy(desc(journeys.createdAt));
}

export async function getJourney(id: string): Promise<Journey | undefined> {
  const [journey] = await db.select().from(journeys).where(eq(journeys.id, id));
  return journey;
}

export async function createJourney(journey: InsertJourney, userId: string): Promise<Journey> {
  const [newJourney] = await db
    .insert(journeys)
    .values({ ...journey, createdBy: userId } as any)
    .returning();
  return newJourney;
}

export async function updateJourney(id: string, journey: Partial<InsertJourney>): Promise<Journey> {
  const [updatedJourney] = await db
    .update(journeys)
    .set({ ...journey, updatedAt: new Date() } as any)
    .where(eq(journeys.id, id))
    .returning();
  return updatedJourney;
}

export async function deleteJourney(id: string): Promise<void> {
  await db.delete(journeys).where(eq(journeys.id, id));
}

// Schedule operations
export async function getSchedules(): Promise<Schedule[]> {
  return await db.select().from(schedules).orderBy(desc(schedules.createdAt));
}

export async function getSchedule(id: string): Promise<Schedule | undefined> {
  const [schedule] = await db.select().from(schedules).where(eq(schedules.id, id));
  return schedule;
}

export async function createSchedule(schedule: InsertSchedule, userId: string): Promise<Schedule> {
  const [newSchedule] = await db
    .insert(schedules)
    .values({ ...schedule, createdBy: userId })
    .returning();
  return newSchedule;
}

export async function updateSchedule(id: string, schedule: Partial<InsertSchedule>): Promise<Schedule> {
  const [updatedSchedule] = await db
    .update(schedules)
    .set(schedule)
    .where(eq(schedules.id, id))
    .returning();
  return updatedSchedule;
}

export async function deleteSchedule(id: string): Promise<void> {
  await db.delete(schedules).where(eq(schedules.id, id));
}

export async function getActiveSchedules(): Promise<Schedule[]> {
  return await db
    .select()
    .from(schedules)
    .where(eq(schedules.enabled, true))
    .orderBy(schedules.createdAt);
}

// Job operations
export async function getJobs(limit = 50): Promise<Job[]> {
  return await db
    .select()
    .from(jobs)
    .orderBy(desc(jobs.createdAt))
    .limit(limit);
}

export async function getJob(id: string): Promise<Job | undefined> {
  const [job] = await db.select().from(jobs).where(eq(jobs.id, id));
  return job;
}

export async function createJob(job: InsertJob): Promise<Job> {
  const [newJob] = await db.insert(jobs).values(job).returning();
  return newJob;
}

export async function updateJob(id: string, updates: Partial<Job>): Promise<Job> {
  const [updatedJob] = await db
    .update(jobs)
    .set(updates)
    .where(eq(jobs.id, id))
    .returning();

  if (!updatedJob) {
    throw new Error(`Job with ID ${id} not found - cannot update non-existent job`);
  }

  return updatedJob;
}

export async function getJobResult(jobId: string): Promise<JobResult | undefined> {
  const [result] = await db.select().from(jobResults).where(eq(jobResults.jobId, jobId));
  return result;
}

export async function createJobResult(result: Omit<JobResult, 'id' | 'createdAt'>): Promise<JobResult> {
  // Sanitize all string fields to prevent PostgreSQL errors with control characters
  const sanitizedResult = {
    ...result,
    stdout: result.stdout ? sanitizeString(result.stdout) : result.stdout,
    stderr: result.stderr ? sanitizeString(result.stderr) : result.stderr,
    artifacts: result.artifacts ? sanitizeObject(result.artifacts) : result.artifacts,
  };

  const [newResult] = await db.insert(jobResults).values(sanitizedResult).returning();
  return newResult;
}

export async function getRunningJobs(): Promise<Job[]> {
  return await db
    .select()
    .from(jobs)
    .where(eq(jobs.status, 'running'))
    .orderBy(jobs.startedAt);
}

export async function getRecentJobs(limit = 10): Promise<Job[]> {
  return await db
    .select()
    .from(jobs)
    .where(inArray(jobs.status, ['completed', 'failed', 'timeout']))
    .orderBy(desc(jobs.finishedAt))
    .limit(limit);
}

export async function getJobsByJourneyId(journeyId: string): Promise<Job[]> {
  return await db
    .select()
    .from(jobs)
    .where(eq(jobs.journeyId, journeyId))
    .orderBy(desc(jobs.createdAt));
}

// Journey credentials operations (authenticated scanning)
export async function createJourneyCredential(journeyCredential: InsertJourneyCredential): Promise<JourneyCredential> {
  const [created] = await db
    .insert(journeyCredentials)
    .values(journeyCredential)
    .returning();
  return created;
}

export async function getJourneyCredentials(journeyId: string): Promise<(JourneyCredential & { credential: Credential })[]> {
  log.info({ journeyId }, 'fetching journey credentials');
  const results = await db
    .select({
      jc: journeyCredentials,
      credential: credentials
    })
    .from(journeyCredentials)
    .leftJoin(credentials, eq(journeyCredentials.credentialId, credentials.id))
    .where(eq(journeyCredentials.journeyId, journeyId))
    .orderBy(journeyCredentials.priority);
  log.info({ rowCount: results.length }, 'journey credentials query returned');

  // Map to plain objects with credential data
  const plainResults = results.map(row => ({
    id: row.jc.id,
    journeyId: row.jc.journeyId,
    credentialId: row.jc.credentialId,
    protocol: row.jc.protocol,
    priority: row.jc.priority,
    createdAt: row.jc.createdAt,
    credential: row.credential ? {
      id: row.credential.id,
      name: row.credential.name,
      username: row.credential.username,
      secretEncrypted: row.credential.secretEncrypted,
      dekEncrypted: row.credential.dekEncrypted,
      domain: row.credential.domain,
      port: row.credential.port,
      description: (row.credential as any).description,
      createdAt: row.credential.createdAt,
      updatedAt: (row.credential as any).updatedAt
    } : null as any
  }));
  log.debug({ credentials: plainResults.map(r => ({
    ...r,
    credential: r.credential ? { ...r.credential, secretEncrypted: '[REDACTED]', dekEncrypted: '[REDACTED]' } : null
  })) }, 'mapped journey credentials with redaction');
  return plainResults;
}

export async function deleteJourneyCredentials(journeyId: string): Promise<void> {
  await db
    .delete(journeyCredentials)
    .where(eq(journeyCredentials.journeyId, journeyId));
}

export async function deleteJourneyCredential(id: string): Promise<void> {
  await db
    .delete(journeyCredentials)
    .where(eq(journeyCredentials.id, id));
}
