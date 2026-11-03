export function Schedule({ rows }: { rows: Row[] }) {
  let balance = 0;
  const [, setState] = useState(0);
  return rows.map((r) => { balance += r.interest - r.wht; return <tr key={r.id}><td>{balance}</td></tr>; });
}
