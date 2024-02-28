#!/bin/bash

# Colors and scan result messages

red_color="\e[31m"
yellow_color="\e[93m"
gray_color="\e[37m"
green_color="\e[32m"
no_color="\e[0m"

result_good="[ ${green_color}GOOD${no_color} ]"
result_suggestion="[ ${gray_color}SUGGESTION${no_color} ]"
result_warning="[ ${yellow_color}WARNING${no_color} ]"
result_alert="[ ${red_color}ALERT${no_color} ]"
