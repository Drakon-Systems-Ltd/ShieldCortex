import { redirect } from 'next/navigation';

export default function GraphRedirect() {
  redirect('/memory?tab=graph');
}
