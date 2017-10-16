import sys

from sqlalchemy import Column, ForeignKey, Integer, String, CheckConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
	__tablename__ = 'user'

	id = Column(Integer, primary_key=True)
	name = Column(String(100), nullable = False)
	email = Column(String(100), nullable= False)
	picture = Column(String(250))

	@property
	def serializeUser(self):
		#Returns object data in easily serialized form
		return {
			'name': self.name,
			'id':self.id,
		}





class Category(Base):
	__tablename__ = 'category'

	name = Column(String(100), CheckConstraint('name !=" "'), nullable = False)
	id = Column(Integer, primary_key=True)
	user_id = Column(Integer, ForeignKey('user.id'))

	user = relationship(User)

	@property
	def serializeCategory(self):
		#Returns object data in easily serialized form
		return {
			'name': self.name,
			'id':self.id,
			'user_id':self.user_id,
		}



class Item(Base):
	__tablename__ = 'item'

	title = Column(String(100), nullable=False)
	id = Column(Integer, primary_key=True)
	description = Column(String(250))
	user_id = Column(Integer, ForeignKey('user.id'))
	category_id = Column(Integer, ForeignKey('category.id'))

	category = relationship(Category)
	user = relationship(User)


	@property
	def serializeItem(self):
		#Returns object data in easily serialized form
		return {
			'title': self.title,
			'id':self.id,
			'description':self.description,
			'user_id':self.user_id,
		}





## Insert at End of file###
engine = create_engine('sqlite:///catalogDb.db')
Base.metadata.create_all(engine)
