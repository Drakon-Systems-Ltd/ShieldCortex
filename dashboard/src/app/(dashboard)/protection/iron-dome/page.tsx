import { redirect } from 'next/navigation';

export default function IronDomeRedirect() {
  redirect('/protection?tab=dome');
}
