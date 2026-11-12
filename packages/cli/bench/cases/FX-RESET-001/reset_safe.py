import secrets
from datetime import timedelta

from fastapi import APIRouter

router = APIRouter()


@router.post("/pin/forgot")
async def forgot_pin(body: ForgotPin):
    code = f"{secrets.randbelow(10**6):06d}"
    await pin_resets.create(user_id=body.user_id, code_hash=sha256(code), expires_at=now() + timedelta(minutes=10))
    await sms.send(body.phone, code)
    return {"sent": True}


@router.post("/pin/reset")
async def reset_pin(body: ResetPin):
    row = await pin_resets.get(code_hash=sha256(body.code))
    if row is None or row.expires_at < now():
        raise HTTPException(status_code=400)
    await wallets.set_pin(row.user_id, body.new_pin)
    await pin_resets.delete(user_id=row.user_id)
    return {"ok": True}
