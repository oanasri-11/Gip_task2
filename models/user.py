from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.session import Base


class User(Base):
    __tablename__="users"
    id=Column(Integer,primary_key=True,index=True)
    user_name=Column(String(50),nullable=False)
    email=Column(String(50),nullable=False,unique=True)
    password=Column(String(255),nullable=False)