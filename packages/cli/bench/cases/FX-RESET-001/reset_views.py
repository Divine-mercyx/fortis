import random

from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/pin/forgot")
async def forgot_pin(body: ForgotPin, request: Request):
    code = str(random.randint(1000, 9999))  # @hit
    link = f"{request.base_url}pin/reset?code={code}"  # @hit
    logger.info("pin reset code %s", code)  # @hit
    await sms.send(body.phone, code)
    return {"sent": True, "code": code}  # @hit


@router.post("/password/reset")
async def reset_password(body: ResetIn):  # @hit
    row = await resets.get(token=body.token)
    await users.set_password(row.user_id, body.new_password)
    return {"ok": True}


@router.post("/password/forgot")
async def forgot_password(body: ForgotIn):
    user = await users.by_email(body.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")  # @hit
    await mailer.send_reset(user)
    return {"ok": True}
