import { redirect } from 'next/navigation';

export default function QuarantineRedirect() {
  redirect('/protection?tab=quarantine');
}
