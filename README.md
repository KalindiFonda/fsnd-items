
#### Item catalog project for the Full Stack Nanodegree by Udacity.

I've been wanting to do a TO DO collecting app for a bit.
so I took the opportunity and did it here. I wanted to have the basics, so it is currently just a list, also because not a fan of simple categories, but maybe I could do categories, based on some of the todo wishes expressed below. Will think about it.

Exciting.

Code heavily based on code from courses:

- [Full Stack Foundations](https://classroom.udacity.com/courses/ud088)
- [Authentication and Authorization](https://classroom.udacity.com/courses/ud330)


#### Getting Started

1. Install Vagrant and VirtualBox
(get files)
2. Launch the Vagrant VM (from the directory where the folder with the project is + a file called Vagrantfile) by typing first `vagrant up` and then `vagrant ssh`.
3. go to `cd /vagrant/name_of_folder` and run the three files: `python database_setup.py`, then `python populate_db.py` and finallt `python project.py` to run the project.
4. Access and test on http://localhost:5000.


#### Future todo wishes:

to do object:
```
#todo: date begin
# created_on = db.Column(db.DateTime, server_default=db.func.now())
# updated_on = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
# http://stackoverflow.com/questions/12154129/how-can-i-automatically-populate-sqlalchemy-database-fields-flask-sqlalchemy
#todo: duration
#todo: eta
#todo: done boolean
```

to do security
```
# todo: I prob exposed db for calls, doing the auth checking within the templates:
# if 'username' not in login_session or creator.id != login_session['user_id']
# if categoryToDelete.user_id != login_session['user_id']:
	return "<script>function myFunction() {alert('You are not authorized to delete this category. Please create your own category in order to delete.');}</script><body onload='myFunction()''>"
```

To run you need to add some secrets in places:
- login section in the main.html - find with TODOINSERT
- and client_secret.json:

1. Google APIs Console — https://console.developers.google.com/apis - choose app
2. Credentials from the menu on the left.
3. Create an OAuth Client ID.
4. consent screen customize
5. choose Web application.
6. set authorized origins
7. Download client secret, there is a button for it.

(check it out here: [instructions](goo.gl/dnNnen))



Yup
