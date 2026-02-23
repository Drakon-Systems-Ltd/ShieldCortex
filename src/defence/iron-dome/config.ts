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

export interface IronDomeConfirmationProtocol {
  red: string[];    // ALWAYS require explicit user confirmation
  amber: string[];  // Announce before proceeding
  green: string[];  // Free to execute silently
}

export interface IronDomeConfig {
  enabled: boolean;
  trustedChannels: string[];
  killPhrase: string;
  requireApproval: string[];
  autoApprove: string[];
  piiRules: IronDomePiiRules;
  subAgentRestrictions: IronDomeSubAgentRestrictions;
  confirmationProtocol: IronDomeConfirmationProtocol;
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
  confirmationProtocol: {
    red: [
      'rm', 'rmdir', 'delete', 'drop', 'truncate', 'purge', 'wipe', 'shred', 'destroy',
      'remove_cron', 'disable_service', 'stop_service', 'revoke_token', 'rotate_credentials',
      'force_push', 'delete_branch', 'modify_firewall', 'modify_netplan', 'modify_systemd',
      'modify_dns', 'bulk_email_delete', 'chmod_recursive', 'chown_recursive',
    ],
    amber: [
      'edit_file', 'install_package', 'update_package', 'create_cron',
      'restart_service', 'modify_config', 'database_migrate',
    ],
    green: [
      'read_file', 'write_new_file', 'git_commit', 'git_push', 'run_report',
      'web_search', 'web_fetch', 'create_directory', 'list_files',
    ],
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
    confirmationProtocol: {
      red: [
        'rm', 'rmdir', 'delete', 'drop', 'truncate', 'purge', 'wipe', 'shred', 'destroy',
        'remove_cron', 'disable_service', 'stop_service', 'revoke_token', 'rotate_credentials',
        'force_push', 'delete_branch', 'modify_firewall', 'modify_netplan', 'modify_systemd',
        'modify_dns', 'bulk_email_delete', 'chmod_recursive', 'chown_recursive',
        'export_pupil_data', 'modify_safeguarding', 'delete_records',
      ],
      amber: [
        'edit_file', 'install_package', 'update_package', 'create_cron',
        'restart_service', 'modify_config', 'database_migrate', 'create_report',
        'modify_records', 'share_data',
      ],
      green: [
        'read_file', 'write_new_file', 'git_commit', 'git_push', 'run_report',
        'web_search', 'web_fetch', 'create_directory', 'list_files',
      ],
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
    confirmationProtocol: {
      red: [
        'rm', 'rmdir', 'delete', 'drop', 'truncate', 'purge', 'wipe', 'shred', 'destroy',
        'remove_cron', 'disable_service', 'stop_service', 'revoke_token', 'rotate_credentials',
        'force_push', 'delete_branch', 'modify_firewall', 'modify_netplan', 'modify_systemd',
        'modify_dns', 'bulk_email_delete', 'chmod_recursive', 'chown_recursive',
        'export_financial_data', 'modify_payroll', 'transfer_funds',
      ],
      amber: [
        'edit_file', 'install_package', 'update_package', 'create_cron',
        'restart_service', 'modify_config', 'database_migrate', 'deploy',
        'modify_permissions', 'export_data',
      ],
      green: [
        'read_file', 'write_new_file', 'git_commit', 'git_push', 'run_report',
        'web_search', 'web_fetch', 'create_directory', 'list_files', 'lint', 'test',
      ],
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
    confirmationProtocol: {
      red: [
        'rm', 'rmdir', 'delete', 'drop', 'truncate', 'purge', 'wipe', 'shred', 'destroy',
        'revoke_token', 'rotate_credentials', 'force_push', 'delete_branch',
      ],
      amber: [
        'edit_file', 'install_package', 'update_package', 'create_cron',
        'restart_service', 'modify_config', 'database_migrate',
      ],
      green: [
        'read_file', 'write_new_file', 'git_commit', 'git_push', 'run_report',
        'web_search', 'web_fetch', 'create_directory', 'list_files', 'api_call', 'create_file',
      ],
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
    confirmationProtocol: {
      red: [
        'rm', 'rmdir', 'delete', 'drop', 'truncate', 'purge', 'wipe', 'shred', 'destroy',
        'remove_cron', 'disable_service', 'stop_service', 'revoke_token', 'rotate_credentials',
        'force_push', 'delete_branch', 'modify_firewall', 'modify_netplan', 'modify_systemd',
        'modify_dns', 'bulk_email_delete', 'chmod_recursive', 'chown_recursive',
        'send_email', 'api_call', 'purchase', 'transfer_funds', 'deploy',
        'export_data', 'share_data', 'modify_permissions', 'install_package',
        'run_script', 'network_request', 'create_file', 'modify_file',
      ],
      amber: [
        'create_cron', 'restart_service', 'modify_config', 'database_migrate',
        'git_push', 'write_new_file',
      ],
      green: [
        'read_file', 'git_commit', 'run_report', 'list_files', 'search',
        'calculate', 'format',
      ],
    },
    profile: 'paranoid',
  },
};
