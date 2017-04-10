from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import ToDo, Base, User

engine = create_engine('sqlite:///todoswithuser.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


User1 = User(name="Dodo Thedoer", email="dodothedoer@gmail.com")
session.add(User1)
session.commit()

ToDo1 = ToDo(user_id=1, name="Wash dishes")
session.add(ToDo1)
session.commit()


ToDo2 = ToDo(user_id=1, name="Catch fishes")
session.add(ToDo2)
session.commit()

print "db populated"
