from datetime import datetime, timedelta,timezone
from typing import Annotated, Optional
import jwt
from fastapi import Header, status
from fastapi.exceptions import HTTPException
from schemas.jwt import JWTPayload, JWTResponsePayload
from setttings import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY


class JWTHandler:
    @staticmethod
    def generate(username: str, exp_timestamp: Optional[int] = None) -> JWTResponsePayload:
        expire_time = ACCESS_TOKEN_EXPIRE_MINUTES
        secret_key = SECRET_KEY

        expires_delta = datetime.now(timezone.utc) + timedelta(minutes=expire_time)

        exp_value = int(exp_timestamp if exp_timestamp is not None else expires_delta.timestamp())

        to_encode = {
            "exp": exp_value,
            "username": username,
        }
        encoded_jwt = jwt.encode(to_encode, secret_key, ALGORITHM)

        return JWTResponsePayload(access=encoded_jwt)
    
    @staticmethod
    def verify_token(auth_token: Annotated[Optional[str], Header()]) -> JWTPayload:
        if not auth_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Auth header not found.",
            )
        jwt_token = auth_token
        try:
            token_data = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])

            if datetime.fromtimestamp(token_data["exp"]) < datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except jwt.exceptions.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return JWTPayload(**token_data)
