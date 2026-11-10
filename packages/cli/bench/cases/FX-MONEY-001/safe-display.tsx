export const Price = ({ amount }: { amount: string }) => <span>{parseFloat(amount).toFixed(2)}</span>;
