import { redirect } from 'next/navigation';

export default function InterceptsRedirect() {
  redirect('/protection?tab=intercepts');
}
