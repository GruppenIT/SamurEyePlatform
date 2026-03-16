import type { TemplateGenerator } from './types';
import { generate as exposedService } from './exposed-service';
import { generate as cveDetected } from './cve-detected';
import { generate as nucleiVulnerability } from './nuclei-vulnerability';
import { generate as webVulnerability } from './web-vulnerability';
import { generate as edrAvFailure } from './edr-av-failure';
import { generate as adSecurityGeneric } from './ad-security-generic';
import { generate as adUsersPasswordNeverExpires } from './ad-users-password-never-expires';
import { generate as adDomainControllerNotFound } from './ad-domain-controller-not-found';
import { generate as adInactiveUsers } from './ad-inactive-users';
import { generate as adUsersOldPasswords } from './ad-users-old-passwords';
import { generate as adPrivilegedGroupMembers } from './ad-privileged-group-members';
import { generate as adObsoleteOs } from './ad-obsolete-os';
import { generate as adInactiveComputers } from './ad-inactive-computers';
import { generate as adWeakPasswordPolicy } from './ad-weak-password-policy';
import { generate as domainAdminCriticalPasswordExpired } from './domain-admin-critical-password-expired';
import { generate as specificInactiveUser } from './specific-inactive-user';
import { generate as privilegedGroupTooManyMembers } from './privileged-group-too-many-members';
import { generate as passwordComplexityDisabled } from './password-complexity-disabled';
import { generate as passwordHistoryInsufficient } from './password-history-insufficient';
import { generate as passwordsNeverExpire } from './passwords-never-expire';
import { generate as inactiveComputerDetected } from './inactive-computer-detected';
import { generate as obsoleteOperatingSystem } from './obsolete-operating-system';
import { generate as bidirectionalTrustDetected } from './bidirectional-trust-detected';
import { generate as domainAdminOldPassword } from './domain-admin-old-password';
import { generate as passwordNeverExpires } from './password-never-expires';

export const templateMap: Record<string, TemplateGenerator> = {
  'exposed-service': exposedService,
  'cve-detected': cveDetected,
  'nuclei-vulnerability': nucleiVulnerability,
  'web-vulnerability': webVulnerability,
  'edr-av-failure': edrAvFailure,
  'ad-security-generic': adSecurityGeneric,
  'ad-users-password-never-expires': adUsersPasswordNeverExpires,
  'ad-domain-controller-not-found': adDomainControllerNotFound,
  'ad-inactive-users': adInactiveUsers,
  'ad-users-old-passwords': adUsersOldPasswords,
  'ad-privileged-group-members': adPrivilegedGroupMembers,
  'ad-obsolete-os': adObsoleteOs,
  'ad-inactive-computers': adInactiveComputers,
  'ad-weak-password-policy': adWeakPasswordPolicy,
  'domain-admin-critical-password-expired': domainAdminCriticalPasswordExpired,
  'specific-inactive-user': specificInactiveUser,
  'privileged-group-too-many-members': privilegedGroupTooManyMembers,
  'password-complexity-disabled': passwordComplexityDisabled,
  'password-history-insufficient': passwordHistoryInsufficient,
  'passwords-never-expire': passwordsNeverExpire,
  'inactive-computer-detected': inactiveComputerDetected,
  'obsolete-operating-system': obsoleteOperatingSystem,
  'bidirectional-trust-detected': bidirectionalTrustDetected,
  'domain-admin-old-password': domainAdminOldPassword,
  'password-never-expires': passwordNeverExpires,
};

export function getTemplate(ruleId: string): TemplateGenerator | undefined {
  return templateMap[ruleId];
}
