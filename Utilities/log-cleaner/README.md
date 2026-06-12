# log-cleaner

Clears Linux system logs and shell history to remove traces after a session.

## Usage

```bash
# List all tracked log files and their status
python3 log_cleaner.py list

# Clear a specific category
python3 log_cleaner.py clear auth
python3 log_cleaner.py clear bash_history

# Clear a specific file
python3 log_cleaner.py clear /var/log/nginx/access.log

# Remove lines matching a pattern (e.g. your IP)
python3 log_cleaner.py grep-remove -f /var/log/auth.log -p "10.10.10.10"

# Full clean (all categories)
python3 log_cleaner.py full
python3 log_cleaner.py full --overwrite --skip apache nginx
```

## Categories

`auth`, `syslog`, `lastlog`, `wtmp`, `btmp`, `bash_history`, `apache`, `nginx`

## Notes

- Most system logs require root
- `--overwrite` writes random data before truncating (more thorough)
- `grep-remove` is useful for surgical removal of specific entries without clearing the whole file
