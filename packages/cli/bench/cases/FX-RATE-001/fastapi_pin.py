from fastapi import APIRouter

router = APIRouter()


@router.post("/pin/verify")
async def verify_pin(body: PinIn):  # @hit
    return await pins.verify(body.user_id, body.pin)


@router.post("/pin/change")
async def change_pin(body: PinChange):  # @hit
    return await pins.change(body.user_id, body.old_pin, body.new_pin)


@router.post("/auth/token")
async def token(form: OAuth2PasswordRequestForm = Depends()):  # @hit
    return await auth.issue(form.username, form.password)


@router.post("/sign-in")
@limiter.limit("5/minute")
async def sign_in(request: Request, body: SignIn):
    return await auth.sign_in(body)


@router.post("/transfers")
async def transfer(body: TransferIn):
    return await transfers.create(body)
