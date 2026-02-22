/**
 * Iron Dome — Configuration types and defaults
 *
 * Defines the IronDomeConfig interface and pre-built profiles
 * for different security postures.
 */

// ── Configuration ──

export interface IronDomePiiRules {
  neverOutput: string[];
  aggregatesOnly: string[];
}

export interface IronDomeSubAgentRestrictions {
  blockedOperations: string[];
  sanitiseContext: boolean;
}

export type IronDomeProfile = 'school' | 'enterprise' | 'personal' | 'paranoid';

export interface IronDomeConfig {
  enabled: boolean;
  trustedChannels: string[];
  killPhrase: string;
  requireApproval: string[];
  autoApprove: string[];
  piiRules: IronDomePiiRules;
  subAgentRestrictions: IronDomeSubAgentRestrictions;
  profile?: IronDomeProfile;
}

// ── Default Configuration ──

export const DEFAULT_IRON_DOME_CONFIG: IronDomeConfig = {
  enabled: false,
  trustedChannels: ['terminal', 'cli'],
  killPhrase: 'full stop',
  requireApproval: ['send_email', 'delete_file', 'api_call', 'purchase', 'transfer_funds'],
  autoApprove: ['read_file', 'search', 'calculate', 'format'],
  piiRules: {
    neverOutput: [],
    aggregatesOnly: [],
  },
  subAgentRestrictions: {
    blockedOperations: [],
    sanitiseContext: false,
  },
};

// ── Pre-built Profiles ──

export const IRON_DOME_PROFILES: Record<IronDomeProfile, Omit<IronDomeConfig, 'enabled'>> = {
  school: {
    trustedChannels: ['terminal', 'cli'],
    killPhrase: 'full stop',
    requireApproval: [
      'send_email', 'delete_file', 'api_call', 'export_data',
      'share_data', 'modify_records', 'create_report',
    ],
    autoApprove: ['read_file', 'search', 'calculate', 'format'],
    piiRules: {
      neverOutput: [
        'pupil_name', 'student_name', 'date_of_birth', 'address',
        'parent_name', 'guardian_name', 'medical_info', 'sen_status',
        'fsm_status', 'ethnicity', 'religion', 'national_insurance',
      ],
      aggregatesOnly: [
        'attendance', 'grades', 'behaviour_points', 'exclusions',
      ],
    },
    subAgentRestrictions: {
      blockedOperations: ['export_pupil_data', 'bulk_email', 'modify_safeguarding'],
      sanitiseContext: true,
    },
    profile: 'school',
  },

  enterprise: {
    trustedChannels: ['terminal', 'cli', 'slack'],
    killPhrase: 'full stop',
    requireApproval: [
      'send_email', 'delete_file', 'api_call', 'purchase',
      'transfer_funds', 'modify_permissions', 'deploy', 'export_data',
    ],
    autoApprove: ['read_file', 'search', 'calculate', 'format', 'lint', 'test'],
    piiRules: {
      neverOutput: [
        'credit_card', 'bank_account', 'ssn', 'tax_id',
        'salary', 'compensation',
      ],
      aggregatesOnly: [
        'revenue', 'expenses', 'headcount',
      ],
    },
    subAgentRestrictions: {
      blockedOperations: ['export_financial_data', 'modify_payroll'],
      sanitiseContext: true,
    },
    profile: 'enterprise',
  },

  personal: {
    trustedChannels: ['terminal', 'cli', 'telegram', 'email'],
    killPhrase: 'full stop',
    requireApproval: [
      'send_email', 'purchase', 'transfer_funds', 'delete_file',
    ],
    autoApprove: [
      'read_file', 'search', 'calculate', 'format',
      'api_call', 'create_file',
    ],
    piiRules: {
      neverOutput: ['password', 'credit_card', 'bank_account'],
      aggregatesOnly: [],
    },
    subAgentRestrictions: {
      blockedOperations: [],
      sanitiseContext: false,
    },
    profile: 'personal',
  },

  paranoid: {
    trustedChannels: ['terminal'],
    killPhrase: 'full stop',
    requireApproval: [
      'send_email', 'delete_file', 'api_call', 'purchase',
      'transfer_funds', 'create_file', 'modify_file', 'deploy',
      'export_data', 'share_data', 'modify_permissions',
      'install_package', 'run_script', 'network_request',
    ],
    autoApprove: ['search', 'calculate', 'format'],
    piiRules: {
      neverOutput: [
        'password', 'credit_card', 'bank_account', 'ssn', 'tax_id',
        'date_of_birth', 'address', 'phone_number', 'email_address',
      ],
      aggregatesOnly: ['salary', 'revenue', 'expenses'],
    },
    subAgentRestrictions: {
      blockedOperations: ['export_data', 'network_request', 'install_package'],
      sanitiseContext: true,
    },
    profile: 'paranoid',
  },
};
