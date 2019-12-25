Developed for a software engineering project, Firewalls-R-Us is a simple GUI for management of Linux firewalls written in python.
FRU uses Uncomplicated Firewall (UFW) to implement rules, and renders several visualizations to aid in user understanding.

## Current Functionality
Only the following 
### View Rules / Rules Dashboard
- Create rule [GET] => go to create rule page.
- Delete rule [POST] => remove rule from database and reload page.
- Logout => go to login page
### Login Page
- Register [POST] => go back to login
- Login [POST] => go to dashboard
### Create Rule page [GET]
- cancel [GET] 
- create rule [POST] => create the rule, add to DB, add to UFW, redirect back to dashboard

##  Usage Guide
1. Ensure you have docker installed
2. Run startup.sh
3. Once complete, navigate to localhost:8000 to test the application
4. When complete, ^C to kill the server
Note: a default test account is available with the login admin:admin

## To do:
- Finish already defined use cases
- Integrate plotly locally using python rather than frontend JS
- Permissions required for running program and modifying ufw
    - Should not be running whole server as sudo
- Outbound firewall rule creation
    - update plotly sunburst diagram to reflect in/out rules
- Investigate how NAT may apply to rules
- Redo parts of frontend with eloquent modern solution
    - Electron based desktop and web app?
    - Heavier JS use for pretty visuals?

## Completed:
- database stuff
- home view (login / register)
- authenticated user landing page - ie view all rules, search filter, navigate to create rule, delete rule button
- create rule
- Register user page
- user interface
- UFW api
