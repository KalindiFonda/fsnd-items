from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    """ create Base object """
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)


class Category(Base):
    """ create Category object """
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    # delete todos that are part of category,
    # ToDo in "" so that it an be used before it is defined.
    to_dos = relationship("ToDo", cascade="all,delete", backref="parent")

    @property
    def serialize(self):
        """Return object data in easily serializeable format for the json"""
        return {
           'name': self.name,
           'id': self.id,
           'user': self.user.name
       }


class ToDo(Base):
    """ create ToDo object """
    __tablename__ = 'to_do'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    # create reationships
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)

    @property
    def serialize(self):
        """Return object data in easily serializeable format for the json"""
        return {
            'name': self.name,
            'user': self.user.name,
            'category': self.category.name
        }


engine = create_engine('sqlite:///todoswithuser.db')
Base.metadata.create_all(engine)
