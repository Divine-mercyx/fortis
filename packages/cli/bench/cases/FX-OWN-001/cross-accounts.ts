export class AccountsService {
  byId(id: string) {
    return this.repo.findOne({ where: { id } });
  }

  mine(id: string) {
    return this.repo.findOne({ where: { id, ownerId: this.auth.userId } });
  }
}
