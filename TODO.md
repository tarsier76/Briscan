# Presentation and user experience:

- Present what is being scanned **DONE**
- Print colored text for each scan result message **DONE**
- Offer remediation steps or suggestions **DONE**

# The script looks for the following:

1. **Network**
- Check for suspicious network connections **DONE**
- Review SSH configuration **DONE** 
- Check for open ports **DONE**

2. **Processes and Memory**
- Detects processes that run with elevated privilleges **DONE**

3. **Users, Groups, Authentication and Passwords**
- Looks for potential avenues for privilege escalation by user accounts **DONE** 
- Verify there are no suspicious accounts **DONE**

4. **Firewall**
- Scans policies and recommends a default deny policy **DONE**

5. **Logging**
- Review system logs for any unusual activities or errors **DONE**

6. **Malware**
- Review the configuration files for unauthorized modifications or anomalies
- Scans system binaries, libraries and kernel objects for signs of rootkits 

7. **Files and Directories**
- File integrity check for critical system files and directories 
- Limit access and permissions on temporary directories
- Check for suspicious hidden files 
- Review user home directories permissions

8. **Kernel and Booting**
- Verify if secure boot is enabled to prevent unauthorized boot loaders
- Check if unnecessary modules are disabled

9. **System**
- Check if updates are available
- Review the scheduled cron jobs for any unfamiliar or suspicious entries
