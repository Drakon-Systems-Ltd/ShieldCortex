import { redirect } from 'next/navigation';

export default function AuditRedirect() {
  redirect('/protection?tab=audit');
}
