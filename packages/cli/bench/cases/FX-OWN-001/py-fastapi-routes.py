from fastapi import APIRouter, Depends
from sqlalchemy import select

router = APIRouter()


@router.get("/wallets/{wallet_id}")
def read_wallet(wallet_id: int, db: Session = Depends(get_db), me: User = Depends(get_current_user)):
    return db.get(Wallet, wallet_id)  # @hit


@router.get("/transfers/{id}")
async def read_transfer(id: UUID, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Transfer).where(Transfer.id == id))  # @hit
    return result.scalar_one()


@router.get("/accounts/{id}")
def read_account(id: int, db=Depends(get_db)):
    return db.query(Account).filter(Account.id == id).first()  # @hit


@router.delete("/loans/{id}")
def delete_loan(id: int, cur=Depends(get_cursor)):
    cur.execute("DELETE FROM loans WHERE id = %s", (id,))  # @hit


@router.get("/payments/{id}")
def read_payment(id: int, db=Depends(get_db)):
    return db.query(Payment).get(id)  # @hit
