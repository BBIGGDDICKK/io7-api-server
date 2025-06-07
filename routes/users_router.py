from fastapi import APIRouter, HTTPException, status, Depends
from models.users import User, NewUser, TokenResponse
from secutils import create_access_token
from secutils import authenticate, create_hash, verify_hash
from environments import Database
import json

router = APIRouter(tags=['Users'])
db = Database(User.Settings.name)

@router.get('/validate_token')
async def valid_token(jwt: str = Depends(authenticate)) -> dict:
    """
    Validate a JWT authentication token.
    
    This endpoint verifies if a provided JWT token is valid and has not expired.
    The validation of the token can be used as the authentication and is used for the other APIs.
    
    Returns:
    - Confirmation message with the validated token
    """
    return {"detail": "Authorized", "token": jwt}

@router.post('/signup')
async def add_user(user: NewUser) -> dict:
    """
    Register a new admin user.
    
    This endpoint creates the admin user for the system.
    No authentication is required as this is used for initial setup, and 
    it will not create another admin user once an admin id is created and exists in the system.
    
    Caution:
    - This endpoint will only work if no users exist in the system
    - Only one admin user can be created
    - The password will be hashed before storage
    - Store the password securely as it cannot be recovered
    
    Returns:
    - Confirmation message with the created user email
    """
    # check if admin user exists and reject if exists
    users = db.getAll()
    if len(users) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Admin User exists already."
        )
    user.password = create_hash(user.password)
    db.insert(user)
    return {
        "message": f"User({user.email}) created successfully"
    }

@router.post("/login", response_model=TokenResponse)
async def login(user: User) -> dict:
    """
    Authenticate a user and generate an access token.
    
    This endpoint verifies user credentials and generates a JWT token for authenticated API access.
    No authentication is required as this is the entry point for the authentication and obtaining a token.
    
    Caution:
    - Ensure proper password security when sending credentials
    - Do not share your access token
    - The token has an expiration time
    
    Returns:
    - Access token and token type for use in subsequent authenticated requests
    """
    qryUser = db.getOne(db.qry.email == user.email)
    if not qryUser:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User(email:{user.email}) does not exist."
        )
    if verify_hash(user.password, qryUser['password']):
        access_token = create_access_token(qryUser['email'])
        return {
            "access_token": access_token,
            "token_type": "Bearer"
        }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid details passed."
    )