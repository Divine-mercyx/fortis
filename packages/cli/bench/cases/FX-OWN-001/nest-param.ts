@Get(':id')
async findOne(@Param('id') id: string) {
  return this.prisma.transaction.findUnique({ where: { id } }); // @hit
}
