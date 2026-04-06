import { redirect } from 'next/navigation';

export default function CloudRedirect() {
  redirect('/settings?tab=cloud');
}
