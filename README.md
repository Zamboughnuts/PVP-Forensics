# PVP-Forensics
Capstone Project for Champlain College MS in Digital Forensics

## Purpose
This project is designed to create a proof of concept of a new way of approaching digital forensic investigations. By using some of the recipes from Miller and Bryce's "Python Digital Forensics Cookbook", I created a script where a forensic disk image could be searched for a list of known hash values, and then files matching those hashes could be extracted to a separate directory.

Ideally, this separate directory would be somewhere that could then be sealed using DD or another tool, so that further investigators could actually open the files in a GUI if necessary. It would also be possible to create a list of subdirectories to search, so that there wouldn't be a concern over searching in too many locations.

## Requirements
This project is a bit particular with it's environment at the moment. This is mostly due to the python libraries that are needed, specifically pytsk3 and pyewf.

* Ubuntu 16.04 LTS
* Python 2.7.12
