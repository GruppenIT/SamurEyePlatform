import type { IStorage } from "./interface";
import * as userOps from "./users";
import * as assetOps from "./assets";
import * as journeyOps from "./journeys";
import * as hostOps from "./hosts";
import * as threatOps from "./threats";
import * as notificationOps from "./notifications";
import * as settingsOps from "./settings";
import * as sessionOps from "./sessions";
import * as subscriptionOps from "./subscription";
import * as databaseInitOps from "./database-init";
import * as edrDeploymentOps from "./edrDeployments";
import * as apiOps from "./apis";
import * as apiEndpointOps from "./apiEndpoints";
import * as apiFindingOps from "./apiFindings";
import * as apiCredentialOps from "./apiCredentials";
import * as mfaOps from "./mfa";
import * as passwordResetOps from "./password-reset";

export type { IStorage } from "./interface";

export class DatabaseStorage implements IStorage {
  // User operations
  getUser = userOps.getUser;
  upsertUser = userOps.upsertUser;
  getUserByEmail = userOps.getUserByEmail;
  updateUserRole = userOps.updateUserRole;
  createUser = userOps.createUser;
  updateUserLastLogin = userOps.updateUserLastLogin;
  updateUserPassword = userOps.updateUserPassword;
  setMustChangePassword = userOps.setMustChangePassword;
  getAllUsers = userOps.getAllUsers;
  getUserMfa = userOps.getUserMfa;
  setUserMfa = userOps.setUserMfa;
  updateBackupCodes = userOps.updateBackupCodes;
  dismissMfaInvitation = userOps.dismissMfaInvitation;

  // Asset operations
  getAssets = assetOps.getAssets;
  getAssetsTree = assetOps.getAssetsTree;
  getAsset = assetOps.getAsset;
  getAssetsByTags = assetOps.getAssetsByTags;
  getAssetsByType = assetOps.getAssetsByType;
  getUniqueTags = assetOps.getUniqueTags;
  createAsset = assetOps.createAsset;
  updateAsset = assetOps.updateAsset;
  deleteAsset = assetOps.deleteAsset;

  // Credential operations
  getCredentials = assetOps.getCredentials;
  getCredential = assetOps.getCredential;
  createCredential = assetOps.createCredential;
  updateCredential = assetOps.updateCredential;
  deleteCredential = assetOps.deleteCredential;

  // Journey operations
  getJourneys = journeyOps.getJourneys;
  getJourney = journeyOps.getJourney;
  createJourney = journeyOps.createJourney;
  updateJourney = journeyOps.updateJourney;
  deleteJourney = journeyOps.deleteJourney;

  // Schedule operations
  getSchedules = journeyOps.getSchedules;
  getSchedule = journeyOps.getSchedule;
  createSchedule = journeyOps.createSchedule;
  updateSchedule = journeyOps.updateSchedule;
  deleteSchedule = journeyOps.deleteSchedule;
  getActiveSchedules = journeyOps.getActiveSchedules;

  // Job operations
  getJobs = journeyOps.getJobs;
  getJob = journeyOps.getJob;
  createJob = journeyOps.createJob;
  updateJob = journeyOps.updateJob;
  getJobResult = journeyOps.getJobResult;
  createJobResult = journeyOps.createJobResult;
  getRunningJobs = journeyOps.getRunningJobs;
  getRecentJobs = journeyOps.getRecentJobs;
  getJobsByJourneyId = journeyOps.getJobsByJourneyId;

  // Journey credentials operations
  createJourneyCredential = journeyOps.createJourneyCredential;
  getJourneyCredentials = journeyOps.getJourneyCredentials;
  deleteJourneyCredentials = journeyOps.deleteJourneyCredentials;
  deleteJourneyCredential = journeyOps.deleteJourneyCredential;

  // Host operations
  getHosts = hostOps.getHosts;
  getHost = hostOps.getHost;
  upsertHost = hostOps.upsertHost;
  updateHost = hostOps.updateHost;
  deleteHost = hostOps.deleteHost;
  getHostByName = hostOps.getHostByName;
  findHostByTarget = hostOps.findHostByTarget;

  // Host enrichment operations
  createHostEnrichment = hostOps.createHostEnrichment;
  getHostEnrichments = hostOps.getHostEnrichments;
  getLatestHostEnrichment = hostOps.getLatestHostEnrichment;

  // Host risk history operations
  createHostRiskHistory = hostOps.createHostRiskHistory;
  getHostRiskHistory = hostOps.getHostRiskHistory;

  // AD Security test results operations
  createAdSecurityTestResults = hostOps.createAdSecurityTestResults;
  getAdSecurityTestResults = hostOps.getAdSecurityTestResults;
  getAdSecurityLatestTestResults = hostOps.getAdSecurityLatestTestResults;

  // Threat operations
  getThreats = threatOps.getThreats;
  getThreatsWithHosts = threatOps.getThreatsWithHosts;
  getThreat = threatOps.getThreat;
  createThreat = threatOps.createThreat;
  updateThreat = threatOps.updateThreat;
  deleteThreat = threatOps.deleteThreat;
  getThreatStats = threatOps.getThreatStats;

  // Threat lifecycle operations
  findThreatByCorrelationKey = threatOps.findThreatByCorrelationKey;
  listOpenThreatsByJourney = threatOps.listOpenThreatsByJourney;
  closeThreatSystem = threatOps.closeThreatSystem;
  upsertThreat = threatOps.upsertThreat;

  // Threat status history operations
  createThreatStatusHistory = threatOps.createThreatStatusHistory;
  getThreatStatusHistory = threatOps.getThreatStatusHistory;

  // Email settings operations
  getEmailSettings = notificationOps.getEmailSettings;
  setEmailSettings = notificationOps.setEmailSettings;
  touchEmailSettingsTest = notificationOps.touchEmailSettingsTest;

  // Notification policy operations
  getNotificationPolicies = notificationOps.getNotificationPolicies;
  getNotificationPolicy = notificationOps.getNotificationPolicy;
  createNotificationPolicy = notificationOps.createNotificationPolicy;
  updateNotificationPolicy = notificationOps.updateNotificationPolicy;
  deleteNotificationPolicy = notificationOps.deleteNotificationPolicy;

  // Notification log operations
  createNotificationLog = notificationOps.createNotificationLog;
  getNotificationLogs = notificationOps.getNotificationLogs;

  // Settings operations
  getSetting = settingsOps.getSetting;
  setSetting = settingsOps.setSetting;
  getAllSettings = settingsOps.getAllSettings;

  // Audit operations
  logAudit = settingsOps.logAudit;
  getAuditLog = settingsOps.getAuditLog;

  // Dashboard operations
  getDashboardMetrics = settingsOps.getDashboardMetrics;

  // System metrics operations
  getSystemMetrics = settingsOps.getSystemMetrics;

  // Active session operations
  createActiveSession = sessionOps.createActiveSession;
  getActiveSessionBySessionId = sessionOps.getActiveSessionBySessionId;
  getActiveSessionsByUserId = sessionOps.getActiveSessionsByUserId;
  updateActiveSessionLastActivity = sessionOps.updateActiveSessionLastActivity;
  deleteActiveSession = sessionOps.deleteActiveSession;
  deleteActiveSessionsByUserId = sessionOps.deleteActiveSessionsByUserId;
  cleanupExpiredSessions = sessionOps.cleanupExpiredSessions;
  getAllActiveSessions = sessionOps.getAllActiveSessions;

  // Login attempt operations
  getLoginAttempt = sessionOps.getLoginAttempt;
  upsertLoginAttempt = sessionOps.upsertLoginAttempt;
  resetLoginAttempts = sessionOps.resetLoginAttempts;
  cleanupOldLoginAttempts = sessionOps.cleanupOldLoginAttempts;

  // Session version operations
  getCurrentSessionVersion = sessionOps.getCurrentSessionVersion;
  incrementSessionVersion = sessionOps.incrementSessionVersion;

  // Appliance subscription operations
  getSubscription = subscriptionOps.getSubscription;
  upsertSubscription = subscriptionOps.upsertSubscription;
  updateHeartbeatSuccess = subscriptionOps.updateHeartbeatSuccess;
  updateHeartbeatFailure = subscriptionOps.updateHeartbeatFailure;

  // Appliance command operations
  saveReceivedCommands = subscriptionOps.saveReceivedCommands;
  getPendingCommands = subscriptionOps.getPendingCommands;
  updateCommandStatus = subscriptionOps.updateCommandStatus;
  getUnreportedCommandResults = subscriptionOps.getUnreportedCommandResults;
  markCommandsReported = subscriptionOps.markCommandsReported;

  // EDR deployment operations
  insertEdrDeployment = edrDeploymentOps.insertEdrDeployment;
  getEdrDeploymentsByJourney = edrDeploymentOps.getEdrDeploymentsByJourney;
  getEdrDeploymentsByJourneyWithHost = edrDeploymentOps.getEdrDeploymentsByJourneyWithHost;

  // API operations — Phase 9 HIER-01, HIER-02, HIER-03, HIER-04, FIND-01
  getApi = apiOps.getApi;
  listApis = apiOps.listApis;
  listApisByParent = apiOps.listApisByParent;
  createApi = apiOps.createApi;
  promoteApiFromBackfill = apiOps.promoteApiFromBackfill;
  listEndpointsByApi = apiEndpointOps.listEndpointsByApi;
  createApiEndpoint = apiEndpointOps.createApiEndpoint;
  upsertApiEndpoint = apiEndpointOps.upsertApiEndpoint;
  listFindingsByEndpoint = apiFindingOps.listFindingsByEndpoint;
  createApiFinding = apiFindingOps.createApiFinding;

  // Phase 10 — API Credentials (CRED-01..04)
  listApiCredentials = apiCredentialOps.listApiCredentials;
  getApiCredential = apiCredentialOps.getApiCredential;
  getApiCredentialWithSecret = apiCredentialOps.getApiCredentialWithSecret;
  createApiCredential = apiCredentialOps.createApiCredential;
  updateApiCredential = apiCredentialOps.updateApiCredential;
  deleteApiCredential = apiCredentialOps.deleteApiCredential;
  resolveApiCredential = apiCredentialOps.resolveApiCredential;

  // MFA email challenges
  createMfaEmailChallenge = mfaOps.createMfaEmailChallenge;
  getActiveChallenges = mfaOps.getActiveChallenges;
  consumeChallenge = mfaOps.consumeChallenge;
  countRecentChallenges = mfaOps.countRecentChallenges;
  cleanupOldChallenges = mfaOps.cleanupOldChallenges;

  // Password reset token operations
  createPasswordResetToken = passwordResetOps.createPasswordResetToken;
  getActivePasswordResetTokens = passwordResetOps.getActivePasswordResetTokens;
  consumePasswordResetToken = passwordResetOps.consumePasswordResetToken;
  consumeAllPasswordResetTokensForUser = passwordResetOps.consumeAllPasswordResetTokensForUser;
  cleanupOldPasswordResetTokens = passwordResetOps.cleanupOldPasswordResetTokens;

  // Database initialization
  async initializeDatabaseStructure() { return databaseInitOps.initializeDatabaseStructure(); }
}

export const storage = new DatabaseStorage();
