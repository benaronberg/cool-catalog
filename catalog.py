#!/usr/bin/env python
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, and_
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item

from flask import session as login_session
import random
import string

app = Flask(__name__)

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/')
@app.route('/catalog')
def catalog():
	categories = session.query(Category).all()
	return render_template('catalog.html', categories=categories)


@app.route('/catalog/<category>')
@app.route('/catalog/<category>/items')
def category(category):
	try:
		mCategory = session.query(Category).filter_by(name = category).one()
		items = session.query(Item).filter_by(category = mCategory).all()
		return render_template('category.html', category=category, items=items)
	except Exception, e:
		print(e)
		return render_template ('404.html'), 404


@app.route('/catalog/newcategory', methods=['GET','POST'])
def newCategory():
	if request.method == 'POST':
		newCategory = Category(name = request.form['name'])
		
		# before commiting the new category check if it already exists
		categories = session.query(Category).all()
		for c in categories:
			if c.name == newCategory.name:
				#flash("%s found in categories already" % newCategory.name)
				return redirect(url_for('category', category = newCategory.name))
		session.add(newCategory)
		session.commit()
		#flash("New category created!")
		return redirect(url_for('category', category = request.form['name']))
	else:
		return render_template('newcategory.html')


@app.route('/editCategory/<category>', methods=['GET','POST'])
def editCategory(category):
	editedCategory = session.query(Category).filter_by(name = category).one()
	if request.method == 'POST':
		if request.form['name']:
			editedCategory.name = request.form['name']
		session.add(editedCategory)
		session.commit()
		#flash("Category modified")
		return redirect(url_for('category', category = editedCategory.name))
	else:
		return render_template('editcategory.html',category = category)


@app.route('/deleteCategory/<category>', methods=['GET','POST'])
def deleteCategory(category):
	if request.method == 'POST':
		categoryToDelete = session.query(Category).filter_by(name = category).one()
		session.delete(categoryToDelete)
		session.commit()
		#flash("Category deleted")
		return redirect(url_for('catalog'))
	else:
		return render_template('deletecategory.html', category=category)


@app.route('/catalog/<category>/<item>')
def item(item, category):
	category = session.query(Category).filter_by(name = category).one()
	item = session.query(Item).filter(and_(Item.name==item,Item.category==category)).one()
	return render_template('item.html', item=item, category=category)


@app.route('/catalog/<category>/<item>/edit', methods=['GET','POST'])
def editItem(item, category):
	mCategory = session.query(Category).filter_by(name = category).one()
	editedItem = session.query(Item).filter(and_(Item.name==item,Item.category==mCategory)).one()
	if request.method == 'POST':
		if request.form['name']:
			editedItem.name = request.form['name']
		if request.form['description']:
			editedItem.description = request.form['description']
		session.add(editedItem)
		session.commit()
		#flash("Item edited")
		return redirect(url_for('category',category = category))
	else:
		return render_template('edititem.html', item=editedItem, category=mCategory)


@app.route('/catalog/<category>/<item>/delete', methods=['GET','POST'])
def deleteItem(item, category):
	mCategory = session.query(Category).filter_by(name = category).one()
	mItem = session.query(Item).filter(and_(Item.name==item,Item.category==mCategory)).one()
	if request.method == 'POST':
		session.delete(mItem)
		session.commit()
		#flash("Item deleted")
		return redirect(url_for('category',category = category))
	else:
		return render_template('deleteitem.html', item=mItem, category=mCategory)


@app.route('/catalog/newitem', methods=['GET','POST'])
def newItem():
	if request.method == 'POST':
		mCategory = session.query(Category).filter_by(name = request.form['category']).one()
		# before commiting the new item check if it already exists
		exists = session.query(Item).filter(and_(Item.name==request.form['name'],Item.category==mCategory)).scalar() is not None
		if not exists:
			newItem = Item(name = request.form['name'], description = request.form['description'], category = mCategory)
			session.add(newItem)
			session.commit()
			#flash("New item created!")
			return redirect(url_for('category', category = mCategory.name))
		else:
			#flash("%s already exists in %s" % request.form['name'], mCategory.name)
			return redirect(url_for('item', item=request.form['name'], category=mCategory.name))
	else: 	
		categories = session.query(Category).all()
		return render_template('newitem.html', categories=categories)	


if __name__ == '__main__':
    #app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)