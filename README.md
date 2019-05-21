# Cool Catalog

This flask based python app provides the user with a generic CRUD-capable database secured with Google Authentication.  Any visitor to the site can view the its contents.  Once authenticated, users have the ability to create, edit, and delete objects in a PostgreSQL database.  Authenticated users also have JSON API endpoints available.

## Getting Started

Run the database_setup.py file, then launch the server by running catalog.py.  Open up a browser to locolhost on port 5000 to see what it looks like.

### Prerequisites

You'll need the following installed on your machine to get the server up and running:
* [Python](https://www.python.org/downloads/)
* [Flask](http://flask.pocoo.org/docs/1.0/installation/)
* [PostgreSQL](https://www.postgresql.org/download/) and install instructions [here](https://www.postgresql.org/docs/9.3/tutorial-install.html)
* [sqlalchemy](https://docs.sqlalchemy.org/en/13/intro.html)
* [oauth2client.client](https://pypi.org/project/oauth2client/)

Alternatively, you can use [Vagrant](https://www.vagrantup.com/docs/installation/) and VirtualBox to set up the environment using the Udacity provided Vagrantfile found [here](https://github.com/udacity/fullstack-nanodegree-vm/blob/master/vagrant/Vagrantfile)

###
Once you have the Prerequisites(#Prerequisites) installed, get the database setup with the following command:
```
python database_setup.py
```
And then run the server using:
```
python catalog.py
```
Now connect to localhost:5000 in a web browser.  You'll have an empty database at this point.  Feel free to populate it with anything you'd like, it's yours to play with!  But first, you'll need to sign in with a Google account using the login button in the top right.

## Acknowledgements

* udacity.com for guidance on writing this code
