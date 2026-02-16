# What do you need to know of python programming if you are a Network and Security Engineer ?

The resources in this repo try to answers to this question. 

This is a lab, and this is more a python lab than an automation lab. We use a security automation scenario which comes from real Threat Hunting use cases in order to get familiar with python programming.

The labs are python challenges. You have to make the python scripts work. But for this you have to solve a lot of programming missions that are missing piece of code and common issues we use to face when we automate Network and Security devices

# A few words about the Automation REST API Lab 

This application is a tiny REST API lab infrastructure which simulates real security solutions.

As student you will go to a Threat Hunting operations you must automate in order to go as fast as possible.

The Backend simulator is a python flask API web server. As student you have to run python http request client which automates your operations.

The web server exposes REST APIs and JSON results. As Student you have to customize the http client in order to query the API server. And you have to parse the result in order to extract malicious objects and block them.

The server simulates completely some REST Security Servers from authentication and query perspective. You have to use the correct product API calls according to their documentation and the simulator replies to your API Call with the extact same answers as the real solutions.

The package in this repo contains some batch files for windows machines that make the installation very fast ( less than 5 Minutes )

But it Can be installed on Mac or Linux through standard python installation.

# Installation

## Prerequisit

You must start with a machine that already has python installed. This project was written in python 3.11 version but should work with python 3.10.


## Very fast install for windows users

For anyone who don't want to waste time.

Download the project into a working directory into your laptop. Unzip the dowloaded file and open a terminal console into the project root directory. Then

- type a
- then type b
- then type c
- then type d
- finally type e

Okay.  The simulator is installed.

Now to run it you just have to type the letter ***a*** from a CMD console openned into the working directory.

You must see the flask server start

## Here under the step by step installation if you don't use the procedure above

## Step 1. Create a working directory

Create a working directory into your laptop. Open a terminal CMD window into it. Name It XDR_BOT for example.

## Step 2. Copy the code into your laptop

The Download ZIP Method

The easiest way for anyone not familiar with git is to copy the ZIP package available for you in this page. Click on the Code button on the top right of this page. And then click on Download ZIP.

Unzip the zip file into your working directory.

The "git clone" method with git client

And here under for those of you who are familiar with Github.

You must have a git client installed into your laptop. Then you can type the following command from a terminal console opened into your working directory.

    git clone https://github.com/pcardotatgit/automation_lab_challenge.git

## Step 3. Go to the code subfolder

Once the code unzipped into your laptop, then Go to the code subfolder.

## Step 4. Create a Python virtual environment

It is still a best practice to create a python virtual environment. Thank to this you will create a dedicated package with requested modules for this application. 

### Create a virtual environment on Windows

    python -m venv venv 

### Create a virtual environment on Linux or Mac

    python3 -m venv venv

Depending on the python version you installed into your Mac you might have to type either 

- python -m venv venv

or maybe

- python3 -m venv venv    : python3 for python version 3.x  

or maybe 

- python3.9 -m venv venv  : if you use the 3.9 python version

And then move to the next step : Activate the virtual environment.

### Activate the virtual environment on Windows

    venv\Scripts\activate

### Activate the virtual environment on Linux or Mac

    source venv/bin/activate    

## Step 5. Install needed python modules

You can install them with the following 2 commands one after the other ( Windows / Mac / Linux ):

The following command might be required if your python version is old.

    python -m pip install --upgrade pip   

Then install required python modules ( Windows / Mac / Linux )

    pip install -r requirements.txt
    
## finalize the installation run the **z_minimum_init_appli.py** script

    python z_minimum_init_appli.py

## Step 7 : run the simulator

    python simulator.py
    
    You should see the flask console indicating you the the web server is listening on port 400
    
# Install the challenge python script

**How to do :**

Open a second CMD console in ./your_working_directory/lab_simulator_v4.1/python_challenge, 

Then install the python virtual environment

- python -m venv venv
- for windows : type : venv\Scripts\activate for Mac and Linux type : source venv/bin/activate  
- pip install -r requirements.txt
- start the backend challenge python script , type : python mission.py

## Run the lab

The principle of the lab is to loop on runing the ***mission.py*** script in order to see when it stop. And then fix the issue
    
The script stops a lot of times, at every key point of the lab.  Either to highlight some information about the APIs we use, or to ask you to fix something which ( voluntarily ) doesn't work. 

Instructions are displayed when the script stop, And the line number where to go is displayed as well. 

Instructions a name MISSIONxx, with xx the number of the mission.

You have to solve 15 MISSION and a lot of common python bugs.

The script tells you when you have complete the lab.

As you run the challenge script, you are supposed to see your API queries in the simulator console. And you see the server replies as well.

For information :

The new_th_mission_original.py script is the original version of the mission.py in case you need to re start from scratch
The mission_solution.py script show the solutions. YOU ARE NOT SUPPOSED TO OPEN IT :-) ! 

The infected hostname is : Demo_AMP_Threat_Audit

# WHAT TO DO NEXT ?

Did you make the mission.py script work ? ...

If the answser is YES ... WHOAW !  CONGRATULATION !!! 

Do You Want More ! ?

Okay, give a try to the challenge-2.py script.   

Same story... you have to make it work.  It is a little bit more complex :-)

DID YOU SOLVE THE 2 CHALLENGES ??

WHOAW !!!   You know what ?  You are ready to go to Network and Security Automation problems !
