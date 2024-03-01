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
	outbound_connections_array=($outbound_connections_ports)

	inbound_connections_ports=$(netstat -tulnap 2>/dev/null | awk -F: '{print $2}' | cut -d " " -f 1 | awk NF)
	inbound_connections_array=($inbound_connections_ports)

	known_services_ports=$(cat /etc/services | awk '{print $2}' | grep -oE '[0-9]+')
	known_services_array=($known_services_ports)

	for outbound_port in "${outbound_connections_array[@]}"; do
		port_found=false
		for known_port in "${known_services_array[@]}"; do
			if [ "$outbound_port" == "$known_port" ]; then
				port_found=true
				break
			fi
		done

		if [ "$port_found" == false ]; then
			printf "Port $outbound_port might be dangerous!\n"
		else
			printf "No suspicious connections!\n"
		fi
	done
}

check_suspicious_network_connections
