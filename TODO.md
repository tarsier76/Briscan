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

6. **Files and Directories** 
- Limit access and permissions on temporary directories **DONE**
- Review user home directories permissions 

7. **Kernel and Booting**
- Verify if secure boot is enabled to prevent unauthorized boot loaders
- Check if unnecessary modules are disabled

8. **System**
- Check if updates are available
- Review the scheduled cron jobs for any unfamiliar or suspicious entries
