from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import ToDo, Base, User, Category

engine = create_engine('sqlite:///todoswithuser.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# create user in db
User1 = User(name="Dodo Thedoer", email="dodothedoer@gmail.com")
session.add(User1)
session.commit()

# Populate categories
Category1 = Category(user_id=1, name="One time thing")
session.add(Category1)
session.commit()

Category2 = Category(user_id=1, name="Daily")
session.add(Category2)
session.commit()

Category3 = Category(user_id=1, name="Yearly")
session.add(Category3)
session.commit()


# populate to dos
ToDo1 = ToDo(user_id=1, name="Wash dishes", category=Category2)
session.add(ToDo1)
session.commit()

ToDo2 = ToDo(user_id=1, name="Catch fishes", category=Category3)
session.add(ToDo2)
session.commit()

ToDo2 = ToDo(user_id=1, name="Give kishes", category=Category1)
session.add(ToDo2)
session.commit()

print "db populated"
