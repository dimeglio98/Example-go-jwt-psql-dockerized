# Example golang app without frontend
The app use jwt to access protected API, everything is in a docker container.

This is a basic app which show how to use Golang (with gin framework) in combination with JWT (and PSQL to store data)

The aim of the app is to make things work, validation in absent although in every app it should be present; I welcome any suggestion to improve the app.

#### Start the app:
CD in project root and then

    docker compose up --build

#### Use the app
The postman collection in the project root is to show how to use the APIs, make sure to login first and use the returned bearer token in the authorization section to use protected API

Existing routes are: login, signup and some simple API to show how things work.

### Note
If the first time you start the app and the engine doesn't connect to db, wait for db to finish bootstrap sequence and simply restart the engine container from docker or command line