#!/bin/bash

# Colors and scan result messages

red_color="\e[31m"
yellow_color="\e[93m"
gray_color="\e[37m"
green_color="\e[32m"
dark_magenta_color="\e[35m"
no_color="\e[0m"

result_good="[ ${green_color}GOOD${no_color} ]"
result_suggestion="[ ${gray_color}SUGGESTION${no_color} ]"
result_warning="[ ${yellow_color}WARNING${no_color} ]"
result_alert="[ ${red_color}ALERT${no_color} ]"

check_suspicious_network_connections() {
	outbound_connections_ports=$(netstat -tulnap 2>/dev/null | awk -F: '{print $3}' | cut -d " " -f 1 | awk NF)
	inbound_connections_ports=$(netstat -tulnap 2>/dev/null | awk -F: '{print $2}' | cut -d " " -f 1 | awk NF)
}

check_suspicious_network_connections
