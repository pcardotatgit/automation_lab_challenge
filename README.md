# automation lab challenge

Backend simulator for the Threat Hunting automation lab.

This application is a tiny flask API server , plus an http request client, used for REST API trainings.

The web server exposes REST APIs and JSON results. Students have to customize the http client in order to query the server and parse result.

The server simulates a few real REST Servers.

It is PrePackaged for windows machines to make installation very fast ( 5 Minutes )

But it Can be installed on Mac or Linux through standard python installation

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

    git clone https://github.com/pcardotatgit/syslog_server_for_XDR_demos.git

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

## Step 7 : run the syslog server

    python simulator.py
    
    You should see the flask console indicating you the the web server is listening on port 400
    
# Run the HTTP Client

The principle of this lab is to run several time the **challenge.py** script. Customize and debug it until it ends with a success message.

Open a second CMD console in the same working directory, then activate the same virtual environment again. An run the script.

    python challenge.py
    
The script stop several  time at every key point of the lab.  Either to highlight some information about the APIs we use, or to ask you to fix something which doesn't work ( voluntarily ).

The script tells you when you have complete the lab.