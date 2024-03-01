#!/bin/bash

# Colors, styling and scan result messages

red_color="\e[31m"
yellow_color="\e[93m"
gray_color="\e[30m"
green_color="\e[32m"
dark_magenta_color="\e[35m"
end_style="\e[0m"
bold_text="\e[1m"

result_good="[ ${green_color}GOOD${end_style} ]"
result_suggestion="[ ${gray_color}SUGGESTION${end_style} ]"
result_warning="[ ${yellow_color}WARNING${end_style} ]"
result_alert="[ ${red_color}ALERT${end_style} ]"

# Scanning info messages

printf "${bold_text}Scanning your system...${end_style}\n"
looking_for_message=$(printf "Looking for")

# Functions

check_network_connections() {
	printf "${looking_for_message} suspicious network connections...\n"

	outbound_connections_ports=$(netstat -tulnap 2>/dev/null | awk -F: '{print $3}' | cut -d " " -f 1 | awk NF)
	outbound_connections_pid=$(netstat -tulnap 2>/dev/null | awk '{print $7,$8}' | grep -E '[0-9]+')
	outbound_connections_array=($outbound_connections_ports)

	known_services_ports=$(cat /etc/services | awk '{print $2}' | grep -oE '[0-9]+')
	known_services_array=($known_services_ports)

	for outbound_port in "${outbound_connections_array[@]}"; do
		if [[ ! "$outbound_port" =~ [0-9]+ ]]; then
			continue
		fi
		port_found=false
		for known_port in "${known_services_array[@]}"; do
			if [ "$outbound_port" -eq "$known_port" ]; then
				port_found=true
				break
			fi
		done

		if [ "$port_found" == false ]; then
			printf "The network connection using port "$outbound_port" seems dangerous!${result_warning}\nYou can kill the process "${red_color}$(ps -p ${outbound_connections_pid%/*} | awk '{print $4}' | sed -n '2p')${end_style}" with PID of "${outbound_connections_pid%/*}" using 'kill -9 <PID>'.${result_suggestion}\n"
		else
			printf "No suspicious network connection found for outbound port ${outbound_port} ${result_good}\n"
		fi
	done
}

check_network_connections
