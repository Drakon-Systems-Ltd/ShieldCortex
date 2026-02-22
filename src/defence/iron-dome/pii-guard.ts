/**
 * Iron Dome — PII Guard
 *
 * Enforces PII protection rules: prevents outputting certain categories
 * of personal data and limits others to aggregates only.
 */

import type { IronDomeConfig, IronDomePiiRules } from './config.js';

export interface PiiCheckResult {
  allowed: boolean;
  violations: PiiViolation[];
  sanitisedContent?: string;
}

export interface PiiViolation {
  category: string;
  rule: 'never_output' | 'aggregates_only';
  reason: string;
}

// ── PII Detection Patterns ──

const PII_PATTERNS: Record<string, RegExp> = {
  // Names
  pupil_name: /\b(?:pupil|student)\s*(?:name|:\s*[A-Z][a-z]+)/gi,
  student_name: /\b(?:student)\s*(?:name|:\s*[A-Z][a-z]+)/gi,
  parent_name: /\b(?:parent|mother|father)\s*(?:name|:\s*[A-Z][a-z]+)/gi,
  guardian_name: /\b(?:guardian|carer)\s*(?:name|:\s*[A-Z][a-z]+)/gi,

  // Personal identifiers
  date_of_birth: /\b(?:d\.?o\.?b\.?|date\s+of\s+birth|born\s+on)\s*[:=]?\s*\d/gi,
  address: /\b(?:address|postcode|zip\s*code)\s*[:=]?\s*\S/gi,
  phone_number: /\b(?:phone|tel(?:ephone)?|mobile|cell)\s*[:=]?\s*[\d+]/gi,
  email_address: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  national_insurance: /\b(?:NI(?:NO)?|national\s+insurance)\s*[:=]?\s*[A-Z]{2}\d/gi,
  ssn: /\b(?:SSN|social\s+security)\s*[:=]?\s*\d{3}[- ]?\d{2}/gi,
  tax_id: /\b(?:tax\s*(?:id|number)|TIN|EIN)\s*[:=]?\s*\d/gi,

  // Financial
  credit_card: /\b(?:card\s*(?:number|#|no)|credit\s*card)\s*[:=]?\s*\d{4}[\s-]?\d{4}/gi,
  bank_account: /\b(?:account\s*(?:number|#|no)|sort\s*code|routing\s*number|IBAN)\s*[:=]?\s*\S/gi,
  salary: /\b(?:salary|wage|pay|compensation|remuneration)\s*[:=]?\s*[£$€\d]/gi,
  password: /\b(?:password|passwd|pwd)\s*[:=]?\s*\S/gi,

  // Sensitive categories
  medical_info: /\b(?:medical|diagnosis|medication|prescription|health\s+condition|disability|allergy)\b/gi,
  sen_status: /\b(?:SEN|SEND|special\s+(?:educational\s+)?needs?|EHCP|IEP)\b/gi,
  fsm_status: /\b(?:FSM|free\s+school\s+meals?|pupil\s+premium)\b/gi,
  ethnicity: /\b(?:ethnicity|ethnic\s+(?:group|origin|background)|race)\s*[:=]/gi,
  religion: /\b(?:religion|faith|religious\s+(?:belief|affiliation))\s*[:=]/gi,

  // Aggregate-compatible categories
  attendance: /\b(?:attendance|absent|present)\s*[:=]?\s*\d/gi,
  grades: /\b(?:grade|mark|score|result|attainment)\s*[:=]?\s*[A-F\d]/gi,
  behaviour_points: /\b(?:behaviour|behavior)\s*(?:points?|score|marks?)\s*[:=]?\s*\d/gi,
  exclusions: /\b(?:exclusion|suspension|expulsion)\s*[:=]?\s*\d/gi,
  revenue: /\b(?:revenue|turnover|sales)\s*[:=]?\s*[£$€\d]/gi,
  expenses: /\b(?:expenses?|costs?|expenditure)\s*[:=]?\s*[£$€\d]/gi,
  headcount: /\b(?:headcount|staff\s+(?:count|number)|FTE)\s*[:=]?\s*\d/gi,
};

/**
 * Check content against PII protection rules.
 */
export function checkPII(
  content: string,
  config: IronDomeConfig,
): PiiCheckResult {
  if (!config.enabled) {
    return { allowed: true, violations: [] };
  }

  const rules = config.piiRules;
  const violations: PiiViolation[] = [];

  // Check never-output categories
  for (const category of rules.neverOutput) {
    const pattern = PII_PATTERNS[category];
    if (pattern) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        violations.push({
          category,
          rule: 'never_output',
          reason: `PII category "${category}" must never be output`,
        });
      }
    }
  }

  // Check aggregates-only categories
  for (const category of rules.aggregatesOnly) {
    const pattern = PII_PATTERNS[category];
    if (pattern) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        violations.push({
          category,
          rule: 'aggregates_only',
          reason: `PII category "${category}" should only be shown as aggregates`,
        });
      }
    }
  }

  return {
    allowed: violations.filter(v => v.rule === 'never_output').length === 0,
    violations,
  };
}
