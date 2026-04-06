import { redirect } from 'next/navigation';

export default function ReviewRedirect() {
  redirect('/memory?tab=review');
}
