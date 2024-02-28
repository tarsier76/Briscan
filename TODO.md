1. **Network**
- Check for suspicious network connections
- Detects unnecessary services
- Review SSH configuration
- Close unnecessary ports 

2. **Processes and Memory**
- Detects processes that run with elevated privilleges

3. **Users, Groups, Authentication and Passwords**
- Looks for potential avenues for privilege escalation by user accounts
- Verify there are no suspicious accounts
- Check the 'sudoers' file for unnecessary user permissions

4. **Firewall**
- Enforces a default deny policy

5. **Logging**
- Log for intrusion detection
- Review system logs for any unusual activities or errors

6. **Malware**
- Review the configuration files for unauthorized modifications or anomalies
- Scans system binaries, libraries and kernel objects for signs of rootkits 

7. **Files and Directories**
- File integrity check for critical system files and directories 
- Check suid and guid permissions
- Limit access and permissions on temporary directories
- Check for suspicious hidden files 
- Review user home directories permissions

8. **Kernel and Booting**
- Verify if secure boot is enabled to prevent unauthorized boot loaders
- Check if unnecessary modules are disabled

9. **System**
- Check if updates are available
- Review the scheduled cron jobs for any unfamiliar or suspicious entries
