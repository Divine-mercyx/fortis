// app/api/auth/login/route.ts style handlers
export async function POST(req: Request) { // @hit
  const { email, password } = await req.json();
  return Response.json(await signIn(email, password));
}
