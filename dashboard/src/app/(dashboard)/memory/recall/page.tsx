import { redirect } from 'next/navigation';

export default function RecallRedirect() {
  redirect('/memory?tab=recall');
}
