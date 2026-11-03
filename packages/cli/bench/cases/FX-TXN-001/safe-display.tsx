export function Balance({ balance }: { balance: number }) {
  const shown = balance.toLocaleString('en-NG');
  return <span>{shown}</span>;
}
