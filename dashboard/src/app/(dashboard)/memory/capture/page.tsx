import { redirect } from 'next/navigation';

export default function CaptureRedirect() {
  redirect('/memory?tab=capture');
}
