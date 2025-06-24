[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTTECHNOLOGIES

pttechnologies Testing tool for identifying technologies used by a web application

## Installation

```
pip install pttechnologies
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
pttechnologies -u https://www.example.com/
pttechnologies -u https://www.example.com/ -ts OSCS OSLPT1 WSHT
```

## Options
```
   -u   --url         <url>           Connect to URL
   -ts  --tests       <test>          Specify one or more tests to perform:
                       OSCS           Test OS detection via Case Sensitivity
                       OSLPT1         Test OS detection via LPT1 path
                       PLLNG          Test programming language detection via file extensions
                       WSHT           Test Apache detection via .ht access rule
                       WSURLLEN       Test URL length behavior to identify web server

   -p   --proxy       <proxy>         Set proxy (e.g. http://127.0.0.1:8080)
   -T   --timeout     <miliseconds>   Set timeout (default 10)
   -t   --threads     <threads>       Set thread count (default 10)
   -c   --cookie      <cookie>        Set cookie
   -a   --user-agent  <a>             Set User-Agent header
   -H   --headers     <header:value>  Set custom header(s)
   -r   --redirects                   Follow redirects (default False)
   -C   --cache                       Cache HTTP communication (load from tmp in future)
   -v   --version                     Show script version and exit
   -h   --help                        Show this help message and exit
   -j   --json                        Output in JSON format
```

## Dependencies
```
ptlibs
```

## License

Copyright (c) 2025 Penterep Security s.r.o.

pttechnologies is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pttechnologies is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with pttechnologies. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!