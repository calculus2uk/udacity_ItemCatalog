from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
 
from database_setup import Base, Category, Item, User
 
engine = create_engine('sqlite:///catalogDb.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine
 
DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

#Dummy User
User1 = User(name="Administrator", email="admin@admin.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()


#Menu for UrbanBurger
category1 = Category(user_id=1, name="soccer")

session.add(category1)
session.commit()


item1 = Item(user_id=1, title = "Boots", description = "Durable footware", category = category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, title = "Gloves", description = "Goalkeeping", category = category1)

session.add(item2)
session.commit()




#Menu for Hockey
category1 = Category(user_id=1, name="hockey")

session.add(category1)
session.commit()


item1 = Item(user_id=1, title = "Stick", description = "Hockey stick", category = category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, title = "skate", description = "footware for ice", category = category1)

session.add(item2)
session.commit()


print "added menu items!"

