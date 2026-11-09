@Entity()
export class Payment {
  @Column('float') // @hit
  amount: number;

  @Column({ type: 'double' }) // @hit
  balance: number;

  @Column('float')
  score: number;

  @Column('decimal')
  total: string;
}
