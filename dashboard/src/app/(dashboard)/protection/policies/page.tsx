import { redirect } from 'next/navigation';

export default function PoliciesRedirect() {
  redirect('/protection?tab=policies');
}
