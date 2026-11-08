@Controller('transactions')
export class TransactionsController {
  @Get(':id')
  async findOne(@Param('id') id: string, @CurrentUser() user: User) {
    return this.prisma.transaction.findFirst({ where: { id, userId: user.id } });
  }
}
