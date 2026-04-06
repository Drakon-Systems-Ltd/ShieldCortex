import { redirect } from 'next/navigation';

export default function TimelineRedirect() {
  redirect('/memory?tab=review');
}
