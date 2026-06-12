# dir-enum

Multithreaded web directory and file enumerator. Brute-forces paths on a web server using a wordlist.

## Usage

```bash
python3 dir_enum.py -u http://target.com -w wordlist.txt
python3 dir_enum.py -u http://target.com -w wordlist.txt -e .php,.html -t 50
python3 dir_enum.py -u http://target.com -w wordlist.txt -o found.txt -v
```

## Options

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-w` | Wordlist path |
| `-t` | Threads (default: 20) |
| `-e` | Extensions to append (e.g. `.php,.html`) |
| `-s` | Status codes to show (default: 200,204,301,302,307,401,403) |
| `-o` | Output file |
| `-v` | Verbose - show all responses |

## Requirements

```bash
pip install -r requirements.txt
```
