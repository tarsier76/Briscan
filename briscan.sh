#!/bin/bash

# Colors, styling and scan result messages

red_color="\e[31m"
yellow_color="\e[93m"
light_blue_color="\e[34m"
green_color="\e[32m"
dark_magenta_color="\e[35m"
end_style="\e[0m"
bold_text="\e[1m"

result_good="[ ${green_color}GOOD${end_style} ]"
result_suggestion="[ ${light_blue_color}SUGGESTION${end_style} ]"
result_warning="[ ${yellow_color}WARNING${end_style} ]"
result_alert="[ ${red_color}ALERT${end_style} ]"
result_info="[ ${dark_magenta_color}INFO${end_style} ]"

# Scanning info messages

printf "${bold_text}Scanning your system...${end_style}\n"

# Functions

check_network_connections() {
	printf "\n${bold_text}Looking for suspicious network connections...${end_style}\n"

	outbound_connections_ports=$(ss -tulnap 2>/dev/null | awk -F: '{print $3}' | cut -d " " -f 1 | awk NF)
	outbound_connections_pid=$(ss -tulnap 2>/dev/null | awk '{print $7,$8}' | grep -E '[0-9]+')
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

check_activated_services() {
	printf "\n${bold_text}Looking for open ports and services...${end_style}\n"
	listening_ports=($(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d ':' -f 2 | awk NF))
	if [[ -n "${listening_ports[0]}" ]]; then
		for port in "${listening_ports[@]}"; do
			port_command=$(sudo lsof -i :${port} 2>/dev/null | sed -n '2p' | awk '{print $1}')
			port_name=$(sudo lsof -i :${port} 2>/dev/null | sed -n '2p' | awk '{print $9}' | awk -F ':' '{print $2}')
			printf "Port $port is open (Command: $port_command, Name: $port_name) $result_info\n"
		done
		printf "\nIf the service is not needed, disabling it will also close the port.\nUse 'systemctl stop <service>' and 'systemctl disable <service>' to stop and disable service at start-up. $result_suggestion\n"
	else
		printf "No ports are opened for inbound connections! $result_good\n"
	fi
}

review_ssh_configuration() {
	printf "\n${bold_text}Reviewing your ssh configuration...${end_style}\n"
	ssh_config_file="/etc/ssh/sshd_config"
	grab_line() {
		local line="$1"
		if grep -m 1 -q "$line" "$ssh_config_file"; then
			exit 0
		else
			printf "Line "$line" is not in '$ssh_config_file' "${result_info}"${result_info}\n"
			exit 1
		fi
	}

	root_login=$(grab_line "PermitRootLogin prohibit-password$")
	if [[ $root_login -eq 0 ]]; then
		if grep -q "^#PermitRootLogin" $ssh_config_file; then
			printf "\nPermitRootLogin is enabled. This is not a concern, but disabling it improves security, in case another user has sudo rights. Uncomment 'PermitRootLogin' in the $ssh_config_file $result_suggestion\n"
		else
			printf "\nPermitRootLogin is disabled. $result_good"
		fi
	fi

	empty_passwords=$(grab_line "PermitEmptyPasswords")
	if [[ $empty_passwords -eq 0 ]]; then
		if grep -q "^#PermitEmptyPasswords" $ssh_config_file; then
			printf "\nPermitEmptyPasswords is commented. Uncomment the line and set it to 'no' in $ssh_config_file in order to disable empty passwords ${result_suggestion}\n"
		else
			printf "\nPermitEmptyPasswords rule is set to no ${result_good}\n"
		fi
	fi

	x11_forwarding=$(grab_line "X11Forwarding")
	if [[ $x11_forwarding -eq 0 ]]; then
		if grep -q -m 1 "X11Forwarding yes" $ssh_config_file; then
			printf "\nX11Forwarding should be set to 'no' in $ssh_config_file in order to reduce attack surface $result_suggestion\n"
		else
			printf "\nX11Forwarding is set to no $result_good\n"
		fi
	fi

	max_login_tries=$(grab_line "MaxAuthTries")
	if [[ $max_login_tries -eq 0 ]]; then
		if grep -q "^#MaxAuthTries" $ssh_config_file; then
			printf "\nMaxAuthTries is commented. Uncomment it in $ssh_config_file to enforce maximum number of login tries before timeout $result_suggestion\n"
		else
			printf "\nMaxAuthTries is enabled $result_good\n"
		fi
	fi
}

check_elevated_processes() {
	printf "\n${bold_text}Looking for suspicious processes that run with elevated privileges...${end_style}\n"
	ps_output=$(ps -U root -u root u)
	cpu_threshold=4
	mem_threshold=4
	suspicious_processes_found=0
	while read -r line; do
		local pid=$(echo "$line" | awk '{$2}')
		local user_name=$(echo "$line" | awk '{$1}')
		local cpu_usage=$(echo "$line" | awk '{$3}')
		local mem_usage=$(echo "$line" | awk '{$4}')
		local process_name=$(echo "$line" | awk '{$11}')
		if [[ "${cpu_usage%.*}" -gt "$cpu_threshold" ]] || [[ "${mem_usage%.*}" -gt "$mem_threshold" ]]; then
			printf "\nSuspicious process running with root privileges: Process: "$process_name" | PID - "$pid" | User - "$user_name" "$result_warning"\nIf it looks familiar, ignore this warning, but further investigation can be done.\n"
		fi
	done <<<"$ps_output"
	if [[ $suspicious_processes_found -eq 0 ]]; then
		printf "\nNo suspicious processes running with elevated privileges. $result_good\n"
	fi
}

check_network_connections
check_activated_services
review_ssh_configuration
check_elevated_processes
